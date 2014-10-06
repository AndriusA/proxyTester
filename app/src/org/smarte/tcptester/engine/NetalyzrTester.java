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
import android.os.Handler;
import android.os.Message;

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

public class NetalyzrTester implements Runnable
{
    public static final String TAG = TcpTester.TAG;
    // Testsuite ID to identify passed messages back to the controller
    public static final int Testsuite_ID = 0001;
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
    private Integer _testPorts[];

    private Handler mHandler;
    public boolean done;

    public NetalyzrTester(Handler handler, Integer testPorts[]) {
        this(handler);
        Log.d(TAG, "NetalyzrTester created with ports");
    }

    public NetalyzrTester(Handler handler) {
        Log.d(TAG, "NetalyzrTester created");
        done = false;
        mHandler = handler;
        proxiedPorts = new ArrayList<Integer>();
        unproxiedPorts = new ArrayList<Integer>();
        // Default ports, but really should invoke via the other constructor
        _testPorts = new Integer[]{80, 443, 993, 8000, 5228, 6969};
    }

    @Override
    public void run() {
        // Netalyzr test order:
        // - CheckLocalAddressTest("checkLocalAddr")
        // - CheckUDPTest("checkUDP")
        // - DNSIPv6SupportTest("checkIPv6DNS")
        // - IPv6Test("checkV6")
        // - MTUTest("checkMTU")
        // - IPv6MTUTest("checkMTUV6")
        // - HiddenProxyTest("checkHiddenProxies")
        Log.d(TAG, "Get Netalyzr UUID");
        TestState.getUUID();

        _tests = new ArrayList();
        _localAddressTest = new CheckLocalAddressTest("checkLocalAddr");
        _tests.add(_localAddressTest);
        _tests.add(new CheckUDPTest("checkUDP"));
        _mtuTest = new MTUTest("checkMTU");
        _tests.add(_mtuTest);

        _hiddenProxyTest = new HiddenProxyTest("checkHiddenProxies", _testPorts);
        _tests.add(_hiddenProxyTest);
    
        Log.d(TAG, "Netalyzr initializing tets");
        for (Test test : _tests) {
            test.init();
        }

        try {
            runNetalyzrTests(_tests);
        } catch (InterruptedException e) { 
            Log.d(TAG, "Test running interrupted");
            sendResponseMessage(TestEngine.TESTSUITE_ERROR_OTHER);
        }

        sendResponseMessage(TestEngine.TESTSUITE_COMPLETED, collectResults());

        synchronized (this) {
            done = true;
            notifyAll();
        }
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
        Log.d(TAG, "Launching tests sequantially");
        for(int currentTest = 0; currentTest < tests.size(); ++currentTest){
            Test test = (Test) tests.get(currentTest);
            runNetalyzrTest(test, currentTest);
            Message msg = new Message();
            msg.what = TestEngine.TEST_COMPLETED;
            mHandler.sendMessage(msg);
        }
        TestState.testsRunning=false;
        return true;
    }

    void sendResponseMessage(int response) {
        sendResponseMessage(response, null);
    }

    void sendResponseMessage(int response, ArrayList<TCPTest> results) {
        Message msg = new Message();
        msg.what = response;
        msg.arg1 = Testsuite_ID;
        if (results != null)
            msg.obj = results;
        mHandler.sendMessage(msg);
    }

    ArrayList<TCPTest> collectResults() {
        // StringBuffer results = new StringBuffer();
        // StringBuffer url = new StringBuffer();
        // for(Test test : _tests){
        //     addTestOutput(test, url, results);
        // }
        // Log.i(TAG, results.toString());

        localAddress = _localAddressTest.localClientAddr;
        globalAddress = _localAddressTest.globalClientAddr;
        mtuProblem = _mtuTest.pathMTUProblem;
        sendMTU = _mtuTest.sendMTU;
        recvMTU = _mtuTest.recvMTU;
        mtuBottleneckAddress = _mtuTest.bottleneckIP;
        proxiedPorts = _hiddenProxyTest.proxiedPorts;
        unproxiedPorts = _hiddenProxyTest.unproxiedPorts;

        InetAddress localAddr = null;
        InetAddress mtuTestServer = null;
        try {
            localAddr = InetAddress.getAllByName(localAddress)[0];
        } catch (Exception e) {
            Log.w(TAG, "Error resolving " + localAddress, e);
        }
        try {
            mtuTestServer = InetAddress.getAllByName(_mtuTest.testServer)[0];
        } catch (Exception e) {
            Log.w(TAG, "Error resolving " + localAddress, e);   
        }
        
        ArrayList<TCPTest> netalyzrTests = new ArrayList<TCPTest>();
        // Only the local and global addresses themselves are relevant for these tests - don't store the others
        netalyzrTests.add(new TCPTest(_localAddressTest.testName+"-LOCAL", 
            TCPTest.CHECK_LOCAL_ADDRESS, localAddress)
        );
        netalyzrTests.add(new TCPTest(_localAddressTest.testName+"-GLOBAL", 
            TCPTest.CHECK_LOCAL_ADDRESS, globalAddress)
        );
        // Source port numbers are not important for all following tests - set to 0
        netalyzrTests.add(new TCPTest(_mtuTest.testName+"-SEND", TCPTest.MTU, 
            localAddr, 0, mtuTestServer, _mtuTest.testPort, 
            mtuProblem, Integer.toString(sendMTU))
        );
        netalyzrTests.add(new TCPTest(_mtuTest.testName+"-RECV", TCPTest.MTU,
            localAddr, 0, mtuTestServer, _mtuTest.testPort,
            mtuProblem, Integer.toString(recvMTU))
        );
        netalyzrTests.add(new TCPTest(_mtuTest.testName+"-bottleneck", TCPTest.MTU, 
            localAddr, 0, mtuTestServer, _mtuTest.testPort, 
            mtuProblem, mtuBottleneckAddress)
        );

        // Store each proxied/unproxied port in a single pair for later reporting
        for (Integer port : proxiedPorts) {
            netalyzrTests.add(
                new TCPTest(_hiddenProxyTest.testName, TCPTest.HIDDEN_PROXY, 
                    localAddr, 0, _hiddenProxyTest.nonResponsiveIP, port, false
                )
            );
        }
        for (Integer port : unproxiedPorts) {
            netalyzrTests.add(
                new TCPTest(_hiddenProxyTest.testName, TCPTest.HIDDEN_PROXY,
                    localAddr, 0, _hiddenProxyTest.nonResponsiveIP, port, true
                )
            );            
        }

        printResults();
        return netalyzrTests;
    }

    void printResults() {
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
}