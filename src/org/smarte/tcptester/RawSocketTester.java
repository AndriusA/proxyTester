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
    private static final String PREFS_NAME = TAG;
    private static final String TESTER_BINARY = "tcptester";
    private static final String IPTABLES_CMD = "iptables -%c OUTPUT -p tcp --tcp-flags RST RST --dport %d -j DROP && iptables --list";

    private SocketTesterServer mTesterServer;
    private Context mContext;
    private ArrayList<String> mServerAddresses;

    public void init(Context context) {
        mServerAddresses = new ArrayList<String>();
        mServerAddresses.add("192.95.61.160");
        mServerAddresses.add("6969");
    }

    public RawSocketTester(String name, Context context) {
        super(name);
        mContext = context;
    }
    

    public int runImpl() throws IOException {
        if (!RootTools.hasBinary(mContext, TESTER_BINARY)) {
            if (RootTools.isRootAvailable() && installNativeBinary(mContext)) {
                Log.d(TAG, "Native binary installed");
            } else {
                return Test.TEST_PROHIBITED;
            }
        }

        // server address and port number are passed as separate String parameters
        // could use any number of endpoints, as long as there is both an address and a port number
        if (mServerAddresses.size() % 2 != 0) {
            Log.e(TAG, "Incorrect number of parameters to RawSocketTester.doInBackground");
            return Test.TEST_ERROR | Test.TEST_ERROR_MALFORMED_URL;
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
        
        Random rng = new Random();
        List<InetAddress> localAddresses = getOwnInetAddresses();
        for (int i = 0; i < localAddresses.size(); i++) {
            byte[] s_addr = localAddresses.get(i).getAddress();
            for (int j = 0; j < mServerAddresses.size(); j = j + 2) {
                InetAddress[] d_addr_l;
                try {
                    d_addr_l = InetAddress.getAllByName(mServerAddresses.get(j));
                } catch (UnknownHostException e) {
                    Log.w(TAG, "Unkown host " + mServerAddresses.get(j));
                    continue;
                }

                Short t = Short.parseShort(mServerAddresses.get(j+1));
                byte[] d_port = new byte[2];
                d_port[1] = (byte)(t & 0xFF);
                d_port[0] = (byte)((t >> 8) & 0xFF);
                for (int k = 0; k < d_addr_l.length; k++) {
                    byte[] d_addr = d_addr_l[k].getAddress();

                    // Random port number in [1025...65536)
                    int r_port = 1024 + 1 + rng.nextInt(65536-1024-1);
                    byte[] s_port = new byte[2];
                    s_port[1] = (byte)(r_port & 0xFF);
                    s_port[0] = (byte)((r_port >> 8) & 0xFF);

                    boolean iptablesAdded = preventRstPort(d_port);
                    // Try runnig the test regardless
                    runTest(s_addr, s_port, d_addr, d_port);
                    if (iptablesAdded) {
                        if (!allowRstPort(d_port)) {
                            Log.e(TAG, "IPTables rule added but not removed!");
                        }
                    }
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
        
        return Test.TEST_COMPLEX; 
    }

    public String getPostResults() {
        String ret = "";
        //TODO: Generate the string results
        return ret;
    }

    private List<InetAddress> getOwnInetAddresses() {
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

    private void runTest(byte[] s_addr, byte[] s_port, byte[] d_addr, byte[] d_port) {    
        ByteArrayOutputStream command = new ByteArrayOutputStream();
        command.write((byte) (1+1+4+2+4+2));
        command.write((byte) 1); // OPCODE
        command.write(s_addr, 0, 4);
        command.write(s_port, 0, 2);
        command.write(d_addr, 0, 4);
        command.write(d_port, 0, 2);

        mTesterServer.send(command.toByteArray());    
        
        byte[] response = mTesterServer.receiveCommand();
        Log.d(TAG, "Response received: " + bytesToHex(response, response[0]));
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
    
    private boolean preventRstPort(byte[] port) {
        ByteBuffer b_port = ByteBuffer.wrap(port);
        short port_num = b_port.getShort();
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

    private boolean allowRstPort(byte[] port) {
        ByteBuffer b_port = ByteBuffer.wrap(port);
        short port_num = b_port.getShort();
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
}
