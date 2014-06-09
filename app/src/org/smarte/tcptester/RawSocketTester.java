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

import com.stericson.RootTools.RootTools;
import com.stericson.RootTools.execution.Shell;
import com.stericson.RootTools.execution.Command;
import com.stericson.RootTools.execution.CommandCapture;
import com.stericson.RootTools.exceptions.RootDeniedException;
import edu.berkeley.icsi.netalyzr.tests.Test;

public class RawSocketTester extends AsyncTask<Void, Integer, Integer>
{
    public static final String TAG = "TCPTester";
    private static final String TESTER_BINARY = "tcptester";
    private static final String IPTABLES_CMD = 
        "iptables -%c OUTPUT -p tcp --tcp-flags RST RST --sport %d --dport %d -d %s -j DROP && iptables --list";

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
        // TODO: also add other common ones: 80 8000 8080
        mServerPorts = new int[]{80, 443, 993, 8000, 5258, 6969};
    }    

    protected Integer doInBackground(Void... none) {
        init();
        if (!RootTools.hasBinary(mActivity, TESTER_BINARY)) {
            if (RootTools.isRootAvailable() && installNativeBinary(mActivity)) {
                Log.d(TAG, "Native binary installed");
            } else {
                Log.d(TAG, "Installing binary failed");
                return Test.TEST_PROHIBITED;
            }
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
        for (TCPTest test : tests) {
            if (isCancelled()) break;
            testNo++;
            publishProgress(1, testNo, tests.size());
            Log.d(TAG, "Running test " + test.name);

            boolean iptablesAdded = false;
            try {
                iptablesAdded = preventRst(test.srcPort, test.dstPort, test.dst);
                // Try runnig the test regardless
                boolean res = mTesterServer.runTest(test.opcode, test.src, test.srcPort, test.dst, test.dstPort, (test.extras != null ? test.extras[0] : 0));
                if (test.opcode == TCPTest.TEST_GET_GLOBAL_IP && res == true) {
                    test.extras = mTesterServer.responseExtra;
                }
                mResults.add(new TCPTest(test, res));
            } catch (Exception e) {
                Log.e(TAG, "Exception while setting iptables rule or running test", e);
            }

            try {
                boolean allowed = allowRst(test.srcPort, test.dstPort, test.dst);
                if (iptablesAdded && !allowed) {
                    Log.e(TAG, "IPTables rule added but not removed!");
                    // Break the for loop
                    break;
                }
            } catch (Exception e) {
                Log.e(TAG, "Exception while setting iptables rule or running test", e);
                break;
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
        return Test.TEST_COMPLEX; 
    }

    protected void onProgressUpdate(Integer... progress) {
         mProgress.incrementProgressBy(progress[0]);
         mProgressText.setText("Running Tests: " + Integer.toString(progress[1]) + "/" + Integer.toString(progress[2]));
     }

    protected void onPostExecute(Integer result) {
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

    private ArrayList<TCPTest> buildTests(InetAddress serverAddress, int[] serverPorts) {
        ArrayList<TCPTest> basicTests = new ArrayList<TCPTest>();
        basicTests.add(new TCPTest("ACK-only", 2));
        basicTests.add(new TCPTest("URG-only", 3));
        // basicTests.add(new TCPTest("ACK-URG", 4));
        basicTests.add(new TCPTest("plain-URG", 5));
        basicTests.add(new TCPTest("ACK-checksum-incorrect", 6));
        basicTests.add(new TCPTest("ACK-checksum", 7));
        // basicTests.add(new TCPTest("URG-URG", 8));
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
        // TODO: add seed in production
        Random rng = new Random();
        List<InetAddress> localAddresses = getOwnInetAddresses();
        completeTests.add(new TCPTest("GlobalIP", TCPTest.TEST_GET_GLOBAL_IP, serverAddress, 443, localAddresses.get(0), 1024 + 1 + rng.nextInt(65536-1024-1)));

        for (TCPTest test : basicTests) {
            for (int dstPort : serverPorts) {
                for (InetAddress localAddress : localAddresses) {
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
