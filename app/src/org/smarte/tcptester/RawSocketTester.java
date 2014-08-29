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

package org.smarte.tcptester;

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


import com.stericson.RootTools.RootTools;
import com.stericson.RootTools.execution.Shell;
import com.stericson.RootTools.execution.Command;
import com.stericson.RootTools.execution.CommandCapture;
import com.stericson.RootTools.exceptions.RootDeniedException;

import edu.berkeley.icsi.netalyzr.tests.Test;
import edu.berkeley.icsi.netalyzr.tests.TestState;
import edu.berkeley.icsi.netalyzr.tests.nat.CheckLocalAddressTest;
import edu.berkeley.icsi.netalyzr.tests.connectivity.CheckUDPTest;
import edu.berkeley.icsi.netalyzr.tests.connectivity.IPv6Test;
import edu.berkeley.icsi.netalyzr.tests.connectivity.MTUTest;
import edu.berkeley.icsi.netalyzr.tests.connectivity.IPv6MTUTest;
import edu.berkeley.icsi.netalyzr.tests.proxy.HiddenProxyTest;

public class RawSocketTester extends AsyncTask<Void, Integer, Integer>
{
    public static final String TAG = "TCPTester";
    private static final String TESTER_BINARY = "tcptester";
    private static final String IPTABLES_CMD = 
        "iptables -%c OUTPUT -p tcp --tcp-flags RST RST --sport %d --dport %d -d %s -j DROP";

    private SocketTesterServer mTesterServer;
    private Context mActivity;
    
    private InetAddress mServerAddress;
    private int[] mServerPorts; 
    private ArrayList<TCPTest> mResults;
    private ProgressBar mProgress;
    private TextView mProgressText, mSubmittedResults;

    public RawSocketTester(Activity activity, ProgressBar progress, TextView progressText) {
        super();
        mActivity = activity;
        mResults = new ArrayList<TCPTest>();
        mProgress = progress;
        mProgressText = progressText;
    }

    public void init() {
        // Only take the first one
        try {
            mServerAddress = InetAddress.getAllByName("192.95.61.161")[0];
        } catch (UnknownHostException e) {
            mServerAddress = null;
        }
        mServerPorts = new int[]{80, 443, 993, 8000, 5228, 6969};
    }    

    protected Integer doInBackground(Void... none) {
        init();
        buildNetalyzrTests();
        if (!RootTools.hasBinary(mActivity, TESTER_BINARY)) {
            if (RootTools.isRootAvailable() && installNativeBinary(mActivity)) {
                Log.d(TAG, "Native binary installed");
            } else {
                Log.d(TAG, "Installing binary failed");
                return Test.TEST_PROHIBITED;
            }
        } else {
            Log.d(TAG, "Native binary already exists");
        }

        if (!RootTools.isRootAvailable() || !RootTools.isAccessGiven()) {
            return Test.TEST_PROHIBITED;
        }
        
        if (mServerAddress == null) {
            return Test.TEST_ERROR | Test.TEST_ERROR_UNKNOWN_HOST;
        }
        ConnectivityManager connMgr = (ConnectivityManager) mActivity.getSystemService(mActivity.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connMgr.getActiveNetworkInfo();
        if ( networkInfo == null || !networkInfo.isConnected() ) {
            Log.d(TAG, "Fatal: Device is currently offline");
            return Test.TEST_ERROR | Test.TEST_ERROR_UNAVAIL;
        }
            
        mTesterServer = new SocketTesterServer();
        mTesterServer.start();
        String address = mTesterServer.getLocalSocketAddress();
        Log.d(TAG, "Local socket address: " + address);
        // Run binary in background to make root shell available for other commands
        RootTools.runBinary(mActivity, TESTER_BINARY, address+" &");
        
        ArrayList<TCPTest> tests = buildTests(mServerAddress, mServerPorts);
        mProgress.setMax(tests.size());
        int testNo = 0;
        boolean iptablesFailed = false;
        for (TCPTest test : tests) {
            if (isCancelled() || iptablesFailed) break;
            testNo++;
            publishProgress(1, testNo, tests.size());
            Log.d(TAG, "Running test " + test.name);

            boolean iptablesAdded = false;
            try {
                iptablesAdded = preventRst(test.srcPort, test.dstPort, test.dst);
            } catch (Exception e) {
                Log.e(TAG, "Exception while setting iptables rule", e);
                iptablesFailed = true;
                break;
            }

            try {
                // Try runnig the test regardless
                boolean res = mTesterServer.runTest(test.opcode, test.src, test.srcPort, test.dst, test.dstPort, (test.extras != null ? test.extras[0] : 0));
                if (test.opcode == TCPTest.TEST_GET_GLOBAL_IP && res == true) {
                    test.extras = mTesterServer.responseExtra;
                }
                mResults.add(new TCPTest(test, res));
            } catch (Exception e) {
                
            }

            try {
                boolean allowed = allowRst(test.srcPort, test.dstPort, test.dst);
                if (iptablesAdded && !allowed) {
                    Log.e(TAG, "IPTables rule added but not removed!");
                    iptablesFailed = true;
                }
            } catch (Exception e) {
                Log.e(TAG, "Exception while resetting iptables", e);
                iptablesFailed = true;
            }
        } 
       
        try {
            // All tests finished, finish the communication thread
            mTesterServer.finish();
            mTesterServer.join();
            Shell.closeAll();
        } catch (InterruptedException e) {
            Log.e(TAG, "LocalServerSocket thread interrupted", e);
        } catch (IOException e) {
            Log.e(TAG, "IOException closing all root shells", e);
        }
        
        Log.i(TAG, Integer.toString(mResults.size()) + " results");
        Log.i(TAG, "Test complete");
        if (iptablesFailed) {
            Log.i(TAG, "Tests aborted due to iptables failure");
            return Test.TEST_ERROR | Test.TEST_ERROR_IO;
        }
        return Test.TEST_COMPLEX; 
    }

    protected void onProgressUpdate(Integer... progress) {
         mProgress.incrementProgressBy(progress[0]);
         mProgressText.setText("Running Tests: " + Integer.toString(progress[1]) + "/" + Integer.toString(progress[2]));
     }

    protected void onPostExecute(Integer result) {
        Log.d(TAG, "execution finished, launching resuls activity");
        super.onPostExecute(result);
        Intent intent = new Intent(mActivity, TcpTesterResults.class);
        if (result == Test.TEST_COMPLEX) {
            intent.putExtra("status", "success");
        } else if (result == Test.TEST_PROHIBITED) {
            intent.putExtra("status", "prohibited");
        } else {
            intent.putExtra("status", "failed");
        }
        intent.putParcelableArrayListExtra("results", mResults);
        mActivity.startActivity(intent);
    }

    protected void buildNetalyzrTests() {
        TestState.getUUID();

        ArrayList<Test> tests = new ArrayList();
        ArrayList<Test> skippedTests = new ArrayList();

        tests.add(new CheckLocalAddressTest("checkLocalAddr"));
        tests.add(new CheckUDPTest("checkUDP"));
        tests.add(new IPv6Test("checkV6"));
        tests.add(new MTUTest("checkMTU"));
        tests.add(new IPv6MTUTest("checkMTUV6"));
        tests.add(new HiddenProxyTest("checkHiddenProxies"));

        for (int i = 0; i < tests.size(); i++) {
            Test test = (Test) tests.get(i);
            test.init();
            if(test.idleMsg == ""){
                Log.d(TAG, "Never set idle message for test " + test.testName);
            }
        }

        try {
            runNetalyzrTests(tests);
        } catch (InterruptedException e) {
            Log.d(TAG, "Test running interrupted");
        }
    }

    protected boolean runNetalyzrTests(ArrayList<Test> tests) throws InterruptedException {
        // Returns false if tests were not run because this client is
        // not the latest version, true otherwise.

        for(int currentTest = 0; currentTest < tests.size(); ++currentTest){
            Test test = (Test) tests.get(currentTest);

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
                }
            } else {
                Log.d(TAG, "Test did not initialize properly.");
            }
        }
        TestState.testsRunning=false;

        StringBuffer results = new StringBuffer();
        StringBuffer url = new StringBuffer();
        for(Test test : tests){
            addTestOutput(test, url, results);
        }
        Log.i(TAG, results.toString());
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


    private ArrayList<TCPTest> buildTests(InetAddress serverAddress, int[] serverPorts) {
        ArrayList<TCPTest> basicTests = new ArrayList<TCPTest>();
        // basicTests.add(new TCPTest("ACK-only", 2));
        // basicTests.add(new TCPTest("URG-only", 3));
        // // basicTests.add(new TCPTest("ACK-URG", 4));
        // basicTests.add(new TCPTest("plain-URG", 5));
        // basicTests.add(new TCPTest("ACK-checksum-incorrect", 6));
        // basicTests.add(new TCPTest("ACK-checksum", 7));
        // basicTests.add(new TCPTest("ACK-data", 15));
        // // basicTests.add(new TCPTest("URG-URG", 8));
        // basicTests.add(new TCPTest("URG-checksum", 9));
        // basicTests.add(new TCPTest("URG-checksum-incorrect", 10));
        // basicTests.add(new TCPTest("Reserved-syn", 11, 1));
        // basicTests.add(new TCPTest("Reserved-syn", 11, 2));
        // basicTests.add(new TCPTest("Reserved-syn", 11, 4));
        // // basicTests.add(new TCPTest("Reserved-syn", 11, 8));
        // basicTests.add(new TCPTest("Reserved-est", 12, 1));
        // basicTests.add(new TCPTest("Reserved-est", 12, 2));
        // basicTests.add(new TCPTest("Reserved-est", 12, 4));
        // // basicTests.add(new TCPTest("Reserved-est", 12, 8));
        // basicTests.add(new TCPTest("ACK-checksum-incorrect-seq", 13));

        ArrayList<TCPTest> completeTests = new ArrayList<TCPTest>();
        Random rng = new Random(System.currentTimeMillis());
        List<InetAddress> localAddresses = getOwnInetAddresses();
        completeTests.add(new TCPTest("GlobalIP", TCPTest.TEST_GET_GLOBAL_IP, serverAddress, 6969, localAddresses.get(0), 1024 + 1 + rng.nextInt(65536-1024-1)));

        for (InetAddress localAddress : localAddresses) {
            for (TCPTest test : basicTests) {
                for (int dstPort : serverPorts) {
                    // Unprivileged random port number in [1025...65536)
                    int srcPort = 1024 + 1 + rng.nextInt(65536-1024-1);
                    completeTests.add(new TCPTest(test, serverAddress, dstPort, localAddress, srcPort));
                }
            }
        }
        Log.d(TAG, Integer.toString(completeTests.size()) + " tests selected");
        return completeTests;
    }

    private List<InetAddress> getOwnInetAddresses() {
        List<InetAddress> ipAddresses = new ArrayList<InetAddress>();
        try {
            Enumeration<NetworkInterface> en;
            for ( en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                // Log.d(TAG, "Checking interface " + intf.toString());
                // Log.d(TAG, "Interface status: " + intf.isLoopback() + intf.isPointToPoint() + intf.isUp());
                // BUGFIX: removed && !intf.isPointToPoint() - broken on CyanogenMod 10.2 for cellular interface
                if (!intf.isLoopback() && intf.isUp() ) {
                    for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {
                        InetAddress inetAddress = enumIpAddr.nextElement();
                        if (!inetAddress.isLinkLocalAddress()) {
                            ipAddresses.add(inetAddress);
                            Log.d(TAG, "Got address " + inetAddress.getHostAddress() + " (interface " + intf.toString() + ")");    
                        }
                    }
                }
            }
        } catch (SocketException e) {
            Log.w(TAG, "Exception while retrieving own IP address", e);
        }

        return ipAddresses;
    }

    private boolean installNativeBinary(Context context) {
        PackageManager m = context.getPackageManager();
        try {
            String s = context.getPackageName();
            PackageInfo p = m.getPackageInfo(s, 0);
            s = p.applicationInfo.sourceDir;

            String arch = Build.CPU_ABI;
            Log.i(TAG, "System architectecture " + arch);
            if (arch.equals("armeabi")) {
                return RootTools.installBinary(context, R.raw.tcptester_armeabi, TESTER_BINARY);
            } else if (arch.equals("armeabi-v7a")) {
                Log.d(TAG, "Installing native binary for armeabi-v7a");
                return RootTools.installBinary(context, R.raw.tcptester_armeabi_v7a, TESTER_BINARY);
            } else if (arch.equals("x86")) {
                return RootTools.installBinary(context, R.raw.tcptester_x86, TESTER_BINARY);
            } else {
                return false;
            }
        } catch ( NameNotFoundException e ) {
            Log.e(TAG, "System architectecture not found", e);
            return false;
        }
    }
    
    private boolean preventRst(int src_port, int dst_port, InetAddress dst) {
        String cmd = String.format(IPTABLES_CMD, 'A', src_port, dst_port, dst.getHostAddress());
        Command shellCmd = new CommandCapture(0, cmd);
        // Log.d(TAG, "Iptables command to execute: " + cmd);
        try {
            Shell.runRootCommand(shellCmd);
            while (true) {
                if (shellCmd.isFinished())
                    break;
                else {
                    // Busy wait for command to finish
                    Thread.sleep(10);
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to enable iptables rule " + cmd, e);
            return false;
        } catch (InterruptedException e) {
            Log.e(TAG, "Failed to enable iptables rule - interrupted while waiting to finish ", e);
            return false;
        } catch (TimeoutException e) {
            Log.e(TAG, "Timed out getting root shell", e);
            return false;
        } catch (RootDeniedException e) {
            Log.e(TAG, "Root denied for shell, quitting", e);
            return false;
        }
        // Log.d(TAG, "iptables rule enabled");
        return true;
    }

    private boolean allowRst(int src_port, int dst_port, InetAddress dst) {
        String cmd = String.format(IPTABLES_CMD, 'D', src_port, dst_port, dst.getHostAddress());
        Command shellCmd = new CommandCapture(1, cmd);
        // Log.d(TAG, "Iptables command to execute: " + cmd);
        try {
            Shell.runRootCommand(shellCmd);
            while (true) {
                if (shellCmd.isFinished())
                    break;
                else {
                    // Log.d(TAG, shellCmd.getCommand() + " running? " + shellCmd.isExecuting());
                    Thread.sleep(10);
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to disable iptables rule " + cmd, e);
            return false;
        } catch (InterruptedException e) {
            Log.e(TAG, "Failed to disable iptables rule - interrupted while waiting to finish ", e);
            return false;
        } catch (TimeoutException e) {
            Log.e(TAG, "Timed out getting root shell", e);
            return false;
        } catch (RootDeniedException e) {
            Log.e(TAG, "Root denied for shell, quitting", e);
            return false;
        }
        // Log.d(TAG, "iptables rule disabled");
        return true;
    }
}
