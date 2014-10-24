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

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import com.stericson.RootTools.exceptions.RootDeniedException;
import com.stericson.RootTools.execution.Command;
import com.stericson.RootTools.execution.CommandCapture;
import com.stericson.RootTools.execution.Shell;
import com.stericson.RootTools.RootTools;
import edu.berkeley.icsi.netalyzr.tests.Test;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.concurrent.TimeoutException;
import java.util.Random;

import org.smarte.tcptester.engine.TestEngine;
import org.smarte.tcptester.R;
import org.smarte.tcptester.TcpTesterResults;

public class RawSocketTester implements Runnable
{
    public static final String TAG = "TCPTester";
    public static final int Testsuite_ID = 0002;
    private static final String TESTER_BINARY = "tcptester";
    private static final String IPTABLES_CMD = 
        "iptables -%c OUTPUT -p tcp --tcp-flags RST RST --sport %d --dport %d -d %s -j DROP";

    private SocketTesterServer mTesterServer;
    private Context mActivity;
    
    private InetAddress mServerAddress, mLocalAddress;
    private Integer[] mServerPorts; 
    private ArrayList<TCPTest> mResults;

    private Handler mHandler;
    public boolean done;

    public RawSocketTester(Context activity, Handler handler,
        String testServer, Integer testPorts[], String localAddress)
    {
        super();
        mActivity = activity;
        mResults = new ArrayList<TCPTest>();
        mHandler = handler;
        done = false;
        init(testServer, testPorts, localAddress);
    }

    private void init(String testServer, Integer testPorts[], String localAddress) {
        // Only take the first one
        try {
            mServerAddress = InetAddress.getAllByName(testServer)[0];
        } catch (UnknownHostException e) {
            mServerAddress = null;
        }
        try {
            mLocalAddress = InetAddress.getAllByName(localAddress)[0];
        } catch (Exception e) {
            mLocalAddress = null;
        }
        mServerPorts = testPorts;
    }    

    @Override
    public void run() {
        if (!RootTools.hasBinary(mActivity, TESTER_BINARY)) {
            if (RootTools.isRootAvailable() && installNativeBinary(mActivity)) {
                Log.d(TAG, "Native binary installed");
            } else {
                Log.d(TAG, "Installing binary failed");
                sendResponseMessage(TestEngine.TESTSUITE_ERROR_PROHIBITED);
                return;
            }
        } else {
            Log.d(TAG, "Native binary already exists");
        }

        if (!RootTools.isRootAvailable() || !RootTools.isAccessGiven()) {
            sendResponseMessage(TestEngine.TESTSUITE_ERROR_PROHIBITED);
            return;
        }
        
        if (mServerAddress == null || mLocalAddress == null) {
            sendResponseMessage(TestEngine.TESTSUITE_ERROR_NETWORK);
            return;
        }
        ConnectivityManager connMgr = (ConnectivityManager) mActivity.getSystemService(mActivity.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connMgr.getActiveNetworkInfo();
        if ( networkInfo == null || !networkInfo.isConnected() ) {
            Log.d(TAG, "Fatal: Device is currently offline");
            sendResponseMessage(TestEngine.TESTSUITE_ERROR_NETWORK);
            return;
        }
            
        mTesterServer = new SocketTesterServer();
        mTesterServer.start();
        String address = mTesterServer.getLocalSocketAddress();
        Log.d(TAG, "Local socket address: " + address);
        // Run binary in background to make root shell available for other commands
        RootTools.runBinary(mActivity, TESTER_BINARY, address+" &");
        
        ArrayList<TCPTest> tests = buildTests(mServerAddress, mServerPorts);
    
        int testNo = 0;
        boolean iptablesFailed = false;
        for (TCPTest test : tests) {
            // Exit immediately if iptables command has not been successful
            if (iptablesFailed)
                break;
            testNo++;
            sendResponseMessage(TestEngine.TEST_COMPLETED);
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
                boolean res = mTesterServer.runTest(test.opcode, test.src, test.srcPort, 
                    test.dst, test.dstPort, test.inputExtras);
                mResults.add(new TCPTest(test, res));
            } catch (Exception e) {
                Log.d(TAG, "Exception caught when running test: ", e);
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
        if (iptablesFailed) {
            Log.i(TAG, "Tests aborted due to iptables failure");
            sendResponseMessage(TestEngine.TESTSUITE_ERROR_NETWORK);
            return;
        }

        sendResponseMessage(TestEngine.TESTSUITE_COMPLETED, mResults);
        Log.d(TAG, "Notifying anyone listening for testsuite completion");
        synchronized(this) {
            done = true;
            notifyAll();
        }
    }

    private ArrayList<TCPTest> buildTests(InetAddress serverAddress, Integer[] serverPorts) {
        ArrayList<TCPTest> basicTests = new ArrayList<TCPTest>();
        basicTests.add(new TCPTest("ACK-only", TCPTest.ACK_ONLY));
        basicTests.add(new TCPTest("URG-only", TCPTest.URG_ONLY));
        // basicTests.add(new TCPTest("ACK-URG", TCPTest.ACK_URG));
        basicTests.add(new TCPTest("plain-URG", TCPTest.PLAIN_URG));
        basicTests.add(new TCPTest("ACK-checksum-incorrect", TCPTest.ACK_CHECKSUM_INCORRECT));
        basicTests.add(new TCPTest("ACK-checksum", TCPTest.ACK_CHECKSUM));
        basicTests.add(new TCPTest("ACK-data", TCPTest.ACK_DATA));
        // basicTests.add(new TCPTest("URG-URG", TCPTest.URG_URG));
        basicTests.add(new TCPTest("URG-checksum", TCPTest.URG_CHECKSUM));
        basicTests.add(new TCPTest("URG-checksum-incorrect", TCPTest.URG_CHECKSUM_INCORRECT));
        basicTests.add(new TCPTest("Reserved-syn", TCPTest.RESERVED_SYN, 1));
        basicTests.add(new TCPTest("Reserved-syn", TCPTest.RESERVED_SYN, 2));
        basicTests.add(new TCPTest("Reserved-syn", TCPTest.RESERVED_SYN, 4));
        // basicTests.add(new TCPTest("Reserved-syn", TCPTest.RESERVED_SYN, 8));
        basicTests.add(new TCPTest("Reserved-est", TCPTest.RESERVED_EST, 1));
        basicTests.add(new TCPTest("Reserved-est", TCPTest.RESERVED_SYN, 2));
        basicTests.add(new TCPTest("Reserved-est", TCPTest.RESERVED_SYN, 4));
        // basicTests.add(new TCPTest("Reserved-est", TCPTest.RESERVED_SYN, 8));
        basicTests.add(new TCPTest("ACK-checksum-incorrect-seq", TCPTest.ACK_CHECKSUM_INCORRECT_SEQ));

        ArrayList<TCPTest> completeTests = new ArrayList<TCPTest>();
        Random rng = new Random(System.currentTimeMillis());
        for (TCPTest test : basicTests) {
            for (int dstPort : serverPorts) {
                // Unprivileged random port number in [1025...65536)
                int srcPort = 1024 + 1 + rng.nextInt(65536-1024-1);
                completeTests.add(new TCPTest(test, serverAddress, dstPort, mLocalAddress, srcPort));
            }
        }
        
        Log.d(TAG, Integer.toString(completeTests.size()) + " tests selected");
        return completeTests;
    }

    void sendResponseMessage(int response) {
        sendResponseMessage(response, null);
    }

    void sendResponseMessage(int response, ArrayList<TCPTest> results) {
        Message msg = new Message();
        Bundle b = new Bundle();
        b.putInt("response", response);
        b.putInt("testsuite", Testsuite_ID);
        if (results != null)
            b.putParcelableArrayList("results", results);
        msg.setData(b);
        mHandler.sendMessage(msg);
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
