/*
 * Copyright (c) 2014 Andrius Aucinas <andrius.aucinas@cl.cam.ac.uk>
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package org.smarte.tcptester.engine;

import android.os.Build;
import java.util.ArrayList;
import android.content.pm.PackageManager.NameNotFoundException;
import java.io.IOException;
import java.net.UnknownHostException;
import android.content.Intent;
import android.content.Context;
import java.util.concurrent.TimeoutException;
import android.app.Activity;
import android.widget.ProgressBar;
import android.os.AsyncTask;
import android.widget.TextView;
import android.net.NetworkInfo;
import java.util.List;
import android.content.pm.PackageManager;
import java.util.Random;
import android.content.pm.PackageInfo;
import java.net.SocketException;
import java.util.Enumeration;
import android.util.Log;
import android.net.ConnectivityManager;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Date;

import edu.berkeley.icsi.netalyzr.tests.Test;
import edu.berkeley.icsi.netalyzr.tests.TestState;
import edu.berkeley.icsi.netalyzr.tests.nat.CheckLocalAddressTest;
import edu.berkeley.icsi.netalyzr.tests.connectivity.CheckUDPTest;
import edu.berkeley.icsi.netalyzr.tests.connectivity.IPv6Test;
import edu.berkeley.icsi.netalyzr.tests.connectivity.MTUTest;
import edu.berkeley.icsi.netalyzr.tests.connectivity.IPv6MTUTest;
import edu.berkeley.icsi.netalyzr.tests.proxy.HiddenProxyTest;
import edu.berkeley.icsi.netalyzr.tests.dns.DNSIPv6SupportTest;

import org.smarte.tcptester.R;
import org.smarte.tcptester.TcpTester;
import org.smarte.tcptester.TcpTesterResults;

public class NetalyzrTester extends AsyncTask<Void, Integer, Integer>
{
    public static final String TAG = TcpTester.TAG;
    // Address info
    public String localAddress;
    public String globalAddress;
    // MTU info
    public boolean mtuProblem;
    public int sendMTU, recvMTU;
    public String mtuBottleneckAddress;
    // Proxied port numbers
    public List<Integer> proxiedPorts;
    public List<Integer> unproxiedPorts;

    private ArrayList<Test> _tests;
    private CheckLocalAddressTest _localAddressTest;
    private MTUTest _mtuTest;
    private HiddenProxyTest _hiddenProxyTest;


    public NetalyzrTester() {
        proxiedPorts = new ArrayList<Integer>();
        unproxiedPorts = new ArrayList<Integer>();
    }

    protected Integer doInBackground(Void... none) {
        // Netalyzr test order:
        // - CheckLocalAddressTest("checkLocalAddr")
        // - CheckUDPTest("checkUDP")
        // - DNSIPv6SupportTest("checkIPv6DNS")
        // - IPv6Test("checkV6")
        // - MTUTest("checkMTU")
        // - IPv6MTUTest("checkMTUV6")
        // - HiddenProxyTest("checkHiddenProxies")
        TestState.getUUID();

        _tests = new ArrayList();
        _localAddressTest = new CheckLocalAddressTest("checkLocalAddr");
        _tests.add(_localAddressTest);
        _tests.add(new CheckUDPTest("checkUDP"));
        _mtuTest = new MTUTest("checkMTU");
        _tests.add(_mtuTest);

        Integer proxyPorts[] = new Integer[]{80, 443, 993, 8000, 5228, 6969};
        _hiddenProxyTest = new HiddenProxyTest("checkHiddenProxies", proxyPorts);
        _tests.add(_hiddenProxyTest);
    
        for (Test test : _tests) {
            test.init();
        }

        try {
            runNetalyzrTests(_tests);
        } catch (InterruptedException e) { 
            Log.d(TAG, "Test running interrupted");
            return Test.TEST_ERROR | Test.TEST_ERROR_NOT_COMPLETED;
        }

        return Test.TEST_COMPLEX;
    }

    protected void onProgressUpdate(Integer... progress) {
    }

    protected void onPostExecute(Integer result) {
        StringBuffer results = new StringBuffer();
        StringBuffer url = new StringBuffer();
        for(Test test : _tests){
            addTestOutput(test, url, results);
        }
        // Log.i(TAG, results.toString());

        localAddress = _localAddressTest.localClientAddr;
        globalAddress = _localAddressTest.globalClientAddr;
        mtuProblem = _mtuTest.pathMTUProblem;
        sendMTU = _mtuTest.sendMTU;
        recvMTU = _mtuTest.recvMTU;
        mtuBottleneckAddress = _mtuTest.bottleneckIP;
        proxiedPorts = _hiddenProxyTest.proxiedPorts;
        unproxiedPorts = _hiddenProxyTest.unproxiedPorts;

        printResults();
    }

    private void printResults() {
        Log.d(TAG, "Addresses:");
        Log.d(TAG, "----------");
        Log.d(TAG, "Local IP address: " + localAddress);
        Log.d(TAG, "Global IP address: " + globalAddress);
        Log.d(TAG, "MTU:");
        Log.d(TAG, "----------");
        Log.d(TAG, "send MTU = " + Integer.toString(sendMTU));
        Log.d(TAG, "recv MTU = " + Integer.toString(recvMTU));
        if (mtuProblem)
            Log.d(TAG, "MTU bottleneck address " + mtuBottleneckAddress);
        Log.d(TAG, "Non-transparent proxying:");
        Log.d(TAG, "----------");
        String sProxiedPorts = "";
        for (Integer port : proxiedPorts)
            sProxiedPorts += port.toString() + "; ";
        Log.d(TAG, "Proxied = " + sProxiedPorts);
        String sUnproxiedPorts = "";
        for (Integer port : unproxiedPorts)
            sUnproxiedPorts += port.toString() + "; ";
        Log.d(TAG, "Unproxied = " + sUnproxiedPorts);
    }


    protected boolean runNetalyzrTest(Test test, int currentTest) throws InterruptedException {
        // Do not change the following text, it is required for
        // parsing the transcript in the DB importer. --cpk
        Log.d(TAG, "");
        Log.d(TAG, "Running test " + currentTest + ": " + test.testName);
        Log.d(TAG, "----------------------------");

        // We run each test in a background thread and wait up to
        // a maximum amount of time specified via each test's
        // timeout member. If a test is not completed at that
        // point, we stop waiting for completion and move on to
        // next test.
        //

        if (test.isReady()){
            try {
                int sleeptime = 50;
                ThreadGroup tg = new ThreadGroup("test-" + currentTest);
                Thread currentTestThread = new Thread(tg, test);
                long startTime = (new Date()).getTime();
                currentTestThread.start();
                while (currentTestThread.isAlive()) {
                    TestState.testsRunning=true;
                    // A polling/latency compromise for detecting
                    // completion of individual tests: the first
                    // completion check happens after 50ms,
                    // subsequent waits increase iteratively by
                    // 25ms up to to a maximum of 500ms.  This
                    // means short tests run MUCH faster while
                    // long-running tests don't impose a lot of
                    // polling overhead in this thread.
                    Thread.sleep(sleeptime);
                    sleeptime = Math.min(500, sleeptime + 25);

                    if ((new Date()).getTime() - startTime > test.timeout) {
                        Log.d(TAG, "Test running overlong, skipping/backgrounding");
                        test.setTimeoutFlag();
                        break;
                    }
                }
            } catch (Exception e) {
                Log.d(TAG, "Test failed with exception", e);
                return false;
            }
        } else {
            Log.d(TAG, "Test did not initialize properly.");
            return false;
        }
        return true;
    }

    protected boolean runNetalyzrTests(ArrayList<Test> tests) throws InterruptedException {
        // Returns false if tests were not run because this client is
        // not the latest version, true otherwise.

        for(int currentTest = 0; currentTest < tests.size(); ++currentTest){
            Test test = (Test) tests.get(currentTest);
            runNetalyzrTest(test, currentTest);
            publishProgress(1, currentTest, tests.size());
        }
        TestState.testsRunning=false;
        return true;
    }

    void addTestOutput(Test test, StringBuffer resultsURL, StringBuffer postEntity) {
        int resultCode = test.getTestResultCode();
        if (!test.ignoreResult) {
            // Update user interface:
            String idleMsg = "gatherResultsFor";
            
            postEntity.append(test.getTestResultString());
            postEntity.append("\nTime" + test.testName + "=" + test.getDuration() + "\n");
            postEntity.append("\nignoredTest" + test.testName + "=False\n");

            // If TEST_NOT_EXECUTED or NOT_COMPLETED, 
            // we assume no post results,
            // This could be due to the test simply running overly
            // long, or it could be a problem.
            if (resultCode != Test.TEST_NOT_EXECUTED && resultCode != (Test.TEST_ERROR | Test.TEST_ERROR_NOT_COMPLETED)) {
                postEntity.append("\n" + test.getPostResults() + "\n");
            }
        } else {
            postEntity.append("\nignoredTest" + test.testName + "=True\n");
        }
    }
}