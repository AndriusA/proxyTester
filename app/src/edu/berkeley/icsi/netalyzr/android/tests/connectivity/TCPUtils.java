package edu.berkeley.icsi.netalyzr.tests.connectivity;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Date;

import edu.berkeley.icsi.netalyzr.tests.*;

public class TCPUtils {

    public static int checkTCP(String server, int port, TCPTestArgs args) {
        return checkTCP(server, port, args, true);
    }

    static int checkTCP(String server, int port, TCPTestArgs args, boolean recordLatency) {
        try {
            return checkTCP(InetAddress.getByName(server), port, args,
                    recordLatency);
        } catch (UnknownHostException e) {
            //Debug.debug("connecting to " + server + ":" + port + ": unknown host");
            return Test.TEST_ERROR | Test.TEST_ERROR_UNKNOWN_HOST;
        }
    }
    
    
    // Get a TCP response from a given query
    byte[] getTCPData(String server, int port, byte[] query, int bufflen)
            throws IOException {

        Socket raw_connection = new Socket();
        InetSocketAddress saddr = new InetSocketAddress(server, port);
        long connectionTime = (new Date()).getTime();
        raw_connection.setSoTimeout(5000);
        raw_connection.connect(saddr, 5 * 1000);
        connectionTime = (new Date()).getTime() - connectionTime;

        Debug.debug("connected to '" + saddr + "' in " + connectionTime + " ms");
        //Debug.debug("Query to server is " + query.length + " bytes");

        raw_connection.getOutputStream().write(query);
        //Debug.debug("Sent request");

        byte buf[] = new byte[bufflen];
        InputStream is = raw_connection.getInputStream();
        int count = 0;

        while (count < bufflen) {
            int res = 0;
            //Debug.debug("Read starting");
            try {
                res = is.read(buf, count, bufflen - count);
                count += res;
            } catch (SocketTimeoutException e) {
                //Debug.debug("Caught timeout exception");
                break;
            }
            if (res < 0)
                break;
        }
        raw_connection.close();
        //Debug.debug("Final count is " + count);

        byte ret[] = new byte[count];
        for (int i = 0; i < count; ++i) {
            ret[i] = buf[i];
        }
        return ret;
    }

    /**
     * Connects to a TCP server on a given port and closes connection
     * @param server
     * @param port
     * @param connectionTimeout
     * @return
     */
    public static long connectTCP_Cellular (InetAddress server, int port, int connectionTimeout, String RNC_State){
        if (port < 0)
            return Test.TEST_ERROR | Test.TEST_ERROR_IO;
        long connectionTime = -1;
        
        try {
            connectionTime = (new Date()).getTime();
            InetSocketAddress addr = new InetSocketAddress(server, port);
            Socket testConn = new Socket();
            testConn.connect(addr, connectionTimeout);
            connectionTime = (new Date()).getTime() - connectionTime;
            testConn.close();
            /*
            Debug.debug("Connected to " + server + ":" + port + " in "
                    + connectionTime + " ms. Initial state: "+RNC_State);
            */
        }
        catch (UnknownHostException e) {
            Debug.debug("connecting to " + TestState.serverName + ":" + port + ": unknown host");
            return -1;
        } catch (IOException e) {
            Debug.debug("connecting to " + TestState.serverName + ":" + port + ": unavailable");
            return -1;
        }

        return connectionTime;
    }
    
    
    static int checkTCP(InetAddress server, int port, TCPTestArgs args,
            boolean recordLatency) {
        if (port < 0)
            return Test.TEST_ERROR | Test.TEST_ERROR_IO;

        if (args == null)
            args = new TCPTestArgs();

        try {
            InetSocketAddress addr = new InetSocketAddress(server, port);
            Socket testConn = new Socket();
            long connectionTime = (new Date()).getTime();
            testConn.connect(addr, args.timeoutMilliSecs);
            connectionTime = (new Date()).getTime() - connectionTime;

            //Debug.debug("Connected to " + server + ":" + port + " in "
            //        + connectionTime + " ms");

            // Record TCP setup latency (separately depending on
            // whether this is the first connection to that port or
            // not) unless we have already recorded the maximum number
            // of datapoints we care about.
            if (recordLatency) {
                if (!TestState.contactedTcpPorts.contains(new Integer(port))) {
                    if (TestState.tcpFirstSetupCount < TestState.maxTcpSetupCount) {
                        TestState.tcpFirstSetupLatency[TestState.tcpFirstSetupCount] = connectionTime;
                        TestState.tcpFirstSetupCount++;
                    }
                } else {
                    if (TestState.tcpSetupCount < TestState.maxTcpSetupCount) {
                        TestState.tcpSetupLatency[TestState.tcpSetupCount] = connectionTime;
                        TestState.tcpSetupCount++;
                    }
                }
            }

            // Record connection attempt to the port.
            TestState.contactedTcpPorts.add(new Integer(port));

            args.localAddr = testConn.getLocalAddress().getHostAddress();
            args.localPort = testConn.getLocalPort();
            args.remoteAddr = testConn.getInetAddress().getHostAddress();

            if (args.todoData > 0) {
                //Debug.debug("reading " + args.todoData + " bytes from socket...");
                byte buf[] = new byte[args.todoData];
                // 5 second timeout to grab data to
                // make sure we grab all the information
                // if a server is a funky MitM for SMTP
                testConn.setSoTimeout(5000);
                InputStream is = testConn.getInputStream();
                StringBuffer recvBuf = new StringBuffer();

                // Grab up to 200 bytes more if things don't stay open.
                while (recvBuf.length() < args.todoData + 200) {
                    int count;
                    try {
                        count = is.read(buf, 0, args.todoData);
                    } catch (SocketTimeoutException e) {
                        break;
                    }
                    if (count < 0)
                        break;
                    recvBuf.append(new String(buf, 0, count));
                }

                // Report data back to caller
                args.recvData = recvBuf.toString();

                if (args.expectedData != null) {
                    boolean match = args.recvData.startsWith(args.expectedData);

                    Debug.debug("TCP test to " + server + ":" + port + ": expected='"
                            + args.expectedData.trim() + "', have '"
                            + args.recvData.trim() + "', match: " + match);
                    if (!match) {
                        testConn.close();
                        return Test.TEST_ERROR | Test.TEST_ERROR_IO_WRONGDATA;
                    }
                }
            }

            testConn.close();
        } catch (UnknownHostException e) {
            Debug.debug("connecting to " + server + ":" + port + ": unknown host");
            return Test.TEST_ERROR | Test.TEST_ERROR_UNKNOWN_HOST;
        } catch (IOException e) {
            Debug.debug("connecting to " + server + ":" + port + ": unavailable");
            return Test.TEST_ERROR | Test.TEST_ERROR_UNAVAIL;
        }

        return Test.TEST_SUCCESS;
    }
}
