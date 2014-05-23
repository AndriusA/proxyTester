package org.smarte.tcptester;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import android.content.pm.PackageManager;
import java.util.Enumeration;
import android.net.ConnectivityManager;
import java.nio.ByteBuffer;
import java.util.Random;
import java.net.SocketException;
import android.content.Context;
import android.content.pm.PackageInfo;
import java.util.List;
import android.net.NetworkInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.util.Log;
import java.util.concurrent.TimeoutException;
import java.net.UnknownHostException;
import android.os.Build;
import java.io.IOException;
import com.stericson.RootTools.RootTools;
import com.stericson.RootTools.execution.Shell;
import com.stericson.RootTools.execution.Command;
import com.stericson.RootTools.execution.CommandCapture;
import com.stericson.RootTools.exceptions.RootDeniedException;
import edu.berkeley.icsi.netalyzr.tests.Test;

public class RawSocketTester extends Test
{
    public static final String TAG = "TCPTester";
    private static final String TESTER_BINARY = "tcptester";
    private static final String IPTABLES_CMD = "iptables -%c OUTPUT -p tcp --tcp-flags RST RST --dport %d -j DROP && iptables --list";

    private SocketTesterServer mTesterServer;
    private Context mContext;
    
    private InetAddress mServerAddress;
    private int[] mServerPorts; 
    private ArrayList<TCPTest> mResults;

    public RawSocketTester(String name, Context context) {
        super(name);
        mContext = context;
        mResults = new ArrayList<TCPTest>();
    }

    public void init() {
        // Only take the first one
        try {
            mServerAddress = InetAddress.getAllByName("192.95.61.160")[0];
        } catch (UnknownHostException e) {
            mServerAddress = null;
        }
        // TODO: also add other common ones: 80 8000 8080
        mServerPorts = new int[]{6969};
    }    

    public int runImpl() throws IOException {
        if (!RootTools.hasBinary(mContext, TESTER_BINARY)) {
            if (RootTools.isRootAvailable() && installNativeBinary(mContext)) {
                Log.d(TAG, "Native binary installed");
            } else {
                Log.d(TAG, "Installing binary failed");
                return Test.TEST_PROHIBITED;
            }
        }
        
        if (mServerAddress == null) {
            return Test.TEST_ERROR | Test.TEST_ERROR_UNKNOWN_HOST;
        }
        ConnectivityManager connMgr = (ConnectivityManager) mContext.getSystemService(mContext.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connMgr.getActiveNetworkInfo();
        if ( !networkInfo.isConnected() ) {
            Log.d(TAG, "Fatal: Device is currently offline");
            return Test.TEST_ERROR | Test.TEST_ERROR_UNAVAIL;
        }
            
        mTesterServer = new SocketTesterServer();
        mTesterServer.start();
        String address = mTesterServer.getLocalSocketAddress();
        Log.d(TAG, "Local socket address: " + address);
        // Run binary in background to make root shell available for other commands
        RootTools.runBinary(mContext, TESTER_BINARY, address+" &");
        
        ArrayList<TCPTest> tests = buildTests(mServerAddress, mServerPorts);
        for (TCPTest test : tests) {
            Log.d(TAG, "Running test " + test.toString());
            boolean iptablesAdded = preventRstPort(test.dstPort);
            // Try runnig the test regardless
            boolean res = mTesterServer.runTest(test.opcode, test.src, test.srcPort, test.dst, test.dstPort);
            mResults.add(new TCPTest(test, res));
            if (iptablesAdded) {
                if (!allowRstPort(test.dstPort)) {
                    Log.e(TAG, "IPTables rule added but not removed!");
                }
            }
        } 
       
        try {
            // All tests finished, finish the communication thread
            mTesterServer.finish();
            mTesterServer.join();
            Shell.closeAll();
        } catch (InterruptedException e) {
            Log.e(TAG, "LocalServerSocket thread interrupted", e);
        }
        
        Log.d(TAG, Integer.toString(mResults.size()) + " results");
        Log.d(TAG, this.getPostResults());
        return Test.TEST_COMPLEX; 
    }

    public String getPostResults() {
        String ret = "";
        for (TCPTest result : mResults) {
            ret += result.toString();
        }
        return ret;
    }

    private ArrayList<TCPTest> buildTests(InetAddress serverAddress, int[] serverPorts) {
        ArrayList<TCPTest> basicTests = new ArrayList<TCPTest>();
        basicTests.add(new TCPTest("ACK-only", 2));
        basicTests.add(new TCPTest("URG-only", 3));
        basicTests.add(new TCPTest("ACK-URG", 4));
        basicTests.add(new TCPTest("plain-URG", 5));
        basicTests.add(new TCPTest("ACK-checksum-incorrect", 6));
        basicTests.add(new TCPTest("ACK-checksum", 7));
        basicTests.add(new TCPTest("URG-URG", 8));
        basicTests.add(new TCPTest("URG-checksum", 9));
        basicTests.add(new TCPTest("URG-checksum-incorrect", 10));
        // basicTests.add(new TCPTest("Reserved-syn", 11));
        // basicTests.add(new TCPTest("Reserved-est", 12));

        ArrayList<TCPTest> completeTests = new ArrayList<TCPTest>();
        // TODO: add seed in production
        Random rng = new Random();
        List<InetAddress> localAddresses = getOwnInetAddresses();
        for (TCPTest test : basicTests) {
            for (int dstPort : serverPorts) {
                for (InetAddress localAddress : localAddresses) {
                    // Unprivileged random port number in [1025...65536)
                    int srcPort = 1024 + 1 + rng.nextInt(65536-1024-1);
                    completeTests.add(new TCPTest(test, serverAddress, dstPort, localAddress, srcPort));
                }
            }
        }
        return completeTests;
    }

    private static List<InetAddress> getOwnInetAddresses() {
        List<InetAddress> ipAddresses = new ArrayList<InetAddress>();
        try {
            Enumeration<NetworkInterface> en;
            for ( en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                if (!intf.isLoopback() && !intf.isPointToPoint() && intf.isUp() ) {
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
        } finally {
            return ipAddresses;
        }
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
    
    private boolean preventRstPort(int port_num) {
        String cmd = String.format(IPTABLES_CMD, 'A', port_num);
        Command shellCmd = new CommandCapture(0, cmd);
        Log.d(TAG, "Iptables command to execute: " + cmd);
        try {
            Shell.runRootCommand(shellCmd);
            while (true) {
                if (shellCmd.isFinished())
                    break;
                else {
                    // Busy wait for command to finish
                    Thread.sleep(100);
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
        Log.d(TAG, "iptables rule enabled");
        return true;
    }

    private boolean allowRstPort(int port_num) {
        String cmd = String.format(IPTABLES_CMD, 'D', port_num);
        Command shellCmd = new CommandCapture(1, cmd);
        Log.d(TAG, "Iptables command to execute: " + cmd);
        try {
            Shell.runRootCommand(shellCmd);
            while (true) {
                if (shellCmd.isFinished())
                    break;
                else {
                    // Log.d(TAG, shellCmd.getCommand() + " running? " + shellCmd.isExecuting());
                    Thread.sleep(100);
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
        Log.d(TAG, "iptables rule disabled");
        return true;
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes, byte length) {
        char[] hexChars = new char[length * 2];
        for ( int j = 0; j < length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public class TCPTest {
        public String name;
        public byte opcode;
        public boolean result = false;
        public InetAddress src;
        public int srcPort;
        public InetAddress dst;
        public int dstPort;
        public TCPTest(String name, int opcode) {
            this.name = name;
            this.opcode = (byte) opcode;
        }
        public TCPTest(TCPTest t, InetAddress dst, int dstPort, InetAddress src, int srcPort) {
            this.name = t.name;
            this.opcode = t.opcode;
            this.dst = dst;
            this.dstPort = dstPort;
            this.src = src;
            this.srcPort = srcPort;
        }
        public TCPTest(TCPTest t, boolean result) {
            this.name = t.name;
            this.opcode = t.opcode;
            this.src = t.src;
            this.srcPort = t.srcPort;
            this.dst = t.dst;
            this.dstPort = t.dstPort;
            this.result = result;
        }
        public String toString() {
            return "Test " + name 
                + " from " + src.getHostAddress() + ":" + Integer.toString(srcPort) 
                + " to " + dst.getHostAddress() + ":" + Integer.toString(dstPort) 
                + (result == true ? " passed" : " failed") + "\n";
        }
    }
}
