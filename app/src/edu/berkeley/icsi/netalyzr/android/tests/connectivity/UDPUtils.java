package edu.berkeley.icsi.netalyzr.tests.connectivity;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Date;

import edu.berkeley.icsi.netalyzr.tests.Debug;
import edu.berkeley.icsi.netalyzr.tests.Test;
import edu.berkeley.icsi.netalyzr.tests.TestState;

public class UDPUtils {


    public static int checkUDP(String server, int port, UDPTestArgs args) throws IOException {
        //Debug.debug("Sending UDP request to " + server + " on port " + port);
        try {
            if (port < 0 || port > 65535)
                return Test.TEST_ERROR | Test.TEST_ERROR_IO;

            DatagramSocket socket = new DatagramSocket();
            InetAddress addr = InetAddress.getByName(server);
            socket.setSoTimeout(args.timeoutMilliSecs);
            socket.connect(addr, port);

            DatagramPacket packet;

            if (args.payload == null) {

                packet = new DatagramPacket(TestState.agentID.getBytes(),
                        TestState.agentID.length(), addr, port);

            } else {
                packet = new DatagramPacket(args.payload, args.payload.length,
                        addr, port);

            }

            for (int i = 0; i < args.numSend; ++i) {
                args.sendPacketTS = (new Date()).getTime();
                socket.send(packet);
                /*
                Debug.debug("UDP socket at "
                        + socket.getLocalAddress().getHostAddress() + ":"
                        + socket.getLocalPort());
                */
                
                try {
                    DatagramPacket d = new DatagramPacket(new byte[8096], 8096);
                    socket.receive(d);
                    args.recvPacketTS = (new Date()).getTime();
                    //Debug.debug("Got datagram of " + d.getLength() + " bytes.");
                    args.addResult(socket.getLocalAddress().getHostAddress(),
                            socket.getLocalPort(), d.getLength());
                    socket.close();
                    return Test.TEST_SUCCESS;
                } catch (SocketTimeoutException e) {
                    //Debug.debug("No data received.");
                }
            }
            socket.close();
        } catch (SocketException e) {
            Debug.debug("Got exception " + e + " on UDP test");
            return Test.TEST_ERROR;
        } catch (UnknownHostException e) {
            Debug.debug("Got exception " + e + " on UDP test");
            return Test.TEST_ERROR | Test.TEST_ERROR_UNKNOWN_HOST;
        }

        return Test.TEST_ERROR | Test.TEST_ERROR_UNAVAIL;
    }
    
    public static byte[] getUDPData(String server, int port, UDPTestArgs args)
            throws IOException {
        return getUDPData(server, port, args, 1024);
    }
    
    /**
     * Used to force a channel acquisition by sending a bulk of UDP datagrams
     * upstream on cellular network tests
     * 
     * @param server
     * @param port
     * @param numberPackets
     * @return
     */
    public static int fillRadioBuffer (InetAddress addr, int port, int timeout, int numDatagrams, int interTime) throws IOException {

        //Debug.debug("Sending UDP request on port " + port+" - Target: fill radio buffer to force DCH promotion");
        
        try {
            if (port < 0 || port > 65535)
                return Test.TEST_ERROR | Test.TEST_ERROR_IO;

            DatagramSocket socket = new DatagramSocket();
            socket.setSoTimeout(timeout);
            socket.connect(addr, port);

            DatagramPacket packet;
            packet = new DatagramPacket(TestState.agentID.getBytes(),
                        TestState.agentID.length(), addr, port);

            for (int i = 0; i < numDatagrams; ++i) {
                socket.send(packet);
                /*
                Debug.debug("UDP socket at "
                        + socket.getLocalAddress().getHostAddress() + ":"
                        + socket.getLocalPort());
                */
                try {
                    DatagramPacket d = new DatagramPacket(new byte[8096], 8096);
                    socket.receive(d);
                    //Debug.debug("Got datagram of " + d.getLength() + " bytes.");
                    
                    socket.close();
                    
                } catch (SocketTimeoutException e) {
                    //Debug.debug("No data received.");
                }
            }
            socket.close();
        } catch (SocketException e) {
            //Debug.debug("Got exception " + e + " on UDP test");
            return Test.TEST_ERROR;
        } catch (UnknownHostException e) {
            //Debug.debug("Got exception " + e + " on UDP test");
            return Test.TEST_ERROR | Test.TEST_ERROR_UNKNOWN_HOST;
        }

        return Test.TEST_SUCCESS;

    }
    

    public static byte[] getUDPData(String server, int port, UDPTestArgs args, int buflen)
            throws IOException {
        try {
            if (port < 0 || port > 65535)
                return null;

            DatagramSocket socket = new DatagramSocket();
            InetAddress addr = InetAddress.getByName(server);
            socket.setSoTimeout(args.timeoutMilliSecs);
            socket.connect(addr, port);

            DatagramPacket packet;

            if (args.payload == null) {

                packet = new DatagramPacket(TestState.agentID.getBytes(),
                        TestState.agentID.length(), addr, port);

            } else {
                packet = new DatagramPacket(args.payload, args.payload.length,
                        addr, port);

            }

            for (int i = 0; i < args.numSend; ++i) {
                args.sendPacketTS = (new Date()).getTime();
                socket.send(packet);
                /*
                Debug.debug("UDP socket at "
                        + socket.getLocalAddress().getHostAddress() + ":"
                        + socket.getLocalPort());
                */
                
                try {
                    byte[] ret = new byte[buflen];

                    DatagramPacket d = new DatagramPacket(ret, buflen);
                    socket.receive(d);
                    args.recvPacketTS = (new Date()).getTime();
                    //Debug.debug("Got datagram of " + d.getLength() + " bytes.");
                    args.addResult(socket.getLocalAddress().getHostAddress(),
                            socket.getLocalPort(), d.getLength());
                    socket.close();
                    // Only return the actual data
                    byte[] ret2 = new byte[d.getLength()];
                    for (int j = 0; j < d.getLength(); ++j) {
                        ret2[j] = ret[j];
                    }
                    return ret2;
                } catch (SocketTimeoutException e) {
                    //Debug.debug("No data received.");
                }
            }
            socket.close();
        } catch (SocketException e) {
            Debug.debug("Got exception " + e + " on UDP test");
            return null;
        } catch (UnknownHostException e) {
            Debug.debug("Got exception " + e + " on UDP test");
            return null;
        }

        return null;
    }
}
