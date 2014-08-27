package edu.berkeley.icsi.netalyzr.tests.nat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;

import edu.berkeley.icsi.netalyzr.localization.Localization;
import edu.berkeley.icsi.netalyzr.tests.Debug;
import edu.berkeley.icsi.netalyzr.tests.Test;
import edu.berkeley.icsi.netalyzr.tests.TestState;
import edu.berkeley.icsi.netalyzr.tests.Utils;
import edu.berkeley.icsi.netalyzr.tests.connectivity.TCPTestArgs;
import edu.berkeley.icsi.netalyzr.tests.connectivity.TCPUtils;

public class CheckLocalAddressTest extends Test {
    
    int num_conns;
    HashSet localAddrs;
    String localPorts;
    String globalPorts;     
    String interfaceAddrs;
    String interfaceAddrsHostname;


    public CheckLocalAddressTest(String name) {
        super(name);
    }
    
    public void init() { 
        idleMsg = Localization.getLocalString(testName);
        localAddrs = new HashSet();
        interfaceAddrs = "";
        interfaceAddrsHostname = "";
        localPorts = "";
        globalPorts = "";
        timeout = 30000;
        num_conns = 10;
    }

    public int runImpl() throws IOException {          
        // Now assumes server is the same as the web
        // host, in order to be consistant.
        String tcpServer = TestState.serverName;
        // shell.getParameter("ECHO_SERVER");
        int tcpPort = Utils.parseInt(TestState.shell.getParameter("TCP_ECHO_PORT"));
        if (tcpPort < 0)
        return Test.TEST_ERROR | Test.TEST_ERROR_IO;

        // Sometimes the default tcpPort is blocked So
        // lets see which one we can get, the primary list
        // being all normally ENCRYPTED ports so likely to
        // be blocked or passthrough, not MITMed.
        int [] tcpPortList = {tcpPort, 22, 465, 
                  585, 993, 995};
        for(int i = 0; i < tcpPortList.length; ++i){
        TCPTestArgs args = new TCPTestArgs(0);
        args.timeoutMilliSecs = 6000;
        int res = TCPUtils.checkTCP(tcpServer, tcpPortList[i], args);
        if (res == TEST_SUCCESS) {
            Debug.debug("Connection to test server on port " + 
              tcpPortList[i] + " succeeded");
            Debug.debug("Using this port for echo tests");
            tcpPort = tcpPortList[i];
            break;
        } 
        Debug.debug("Connection " + i + 
              " failed returned result code " + res);
        }           

        // The server returns in the connection payload
        // the global address it sees our connections
        // coming from. We attempt to extract this address
        // in repeated connections until we succeed.
        boolean globalAddrRead = false;
        int succ_conns = 0;

        for (int i = 0; i < num_conns; i++) {
        TCPTestArgs args = new TCPTestArgs(32);
        try {
            int res = TCPUtils.checkTCP(tcpServer, tcpPort, args);
            if (res == TEST_SUCCESS) {
            succ_conns++;
            } else {
            Debug.debug("Connection " + i + " failed with result code " + res);             
            // Wait a little while and try again.
            try{ Thread.sleep(500); }
            catch (InterruptedException e) { }
            continue;
            }
        } catch (ThreadDeath e){
            // This doesn't always work, but almost
            // always, when things go overlong.

            if(i < 3){
            return Test.TEST_NOT_EXECUTED;
            }
            num_conns = i + 1;
        }
        

        if(TestState.localClientAddr.equals("0.0.0.0")){
            TestState.localClientAddr = "" + args.localAddr;
        }
        Debug.debug("Local socket is " + args.localAddr +
              ":" + args.localPort);
        localAddrs.add(args.localAddr);
        localPorts += Integer.toString(args.localPort);
        if (i < num_conns - 1)
            localPorts += ",";

        Debug.debug ("Now getting global port");
        int sep = args.recvData.indexOf(":");
        if (sep < 0) {
            Debug.debug("Received data invalid: \"" +
              args.recvData + "\"");
            continue;
        }
        Debug.debug("Global port is " + args.recvData.substring(sep+1));
        try {
            int globalPort = Integer.parseInt(args.recvData.substring(sep + 1).trim());
            globalPorts += Integer.toString(globalPort);
            if (i < num_conns - 1)
            globalPorts += ",";
        } catch (java.lang.NumberFormatException e){
            Debug.debug("Global port number failed to parse");
        }


        // Global address extraction is below, skip if
        // done before.
        if (globalAddrRead)
            continue;

        if (args.recvData == null) {
            Debug.debug("No data read from echo server");
            continue;
        }

        TestState.globalClientAddr = args.recvData.substring(0, sep);
        TestState.globalClientCheckedPort = tcpPort;
        
        // This default port is also one we will test
        // using the traceback proxy detector:
        TestState.tracebackProxyPorts.add(new Integer(tcpPort));

        // XXX should validate here that this is
        // actually an IP address! See
        // 4b65b5d3-5669-2f438b82-b47d-4ca1-a600 for
        // an example where it's not. --cpk

        Debug.debug("Global IP address is " + TestState.globalClientAddr);
        Debug.debug("Fetched using port " + TestState.globalClientCheckedPort);
        globalAddrRead = true;
        }
        
        if (! globalAddrRead) {
        Debug.debug("Failed to extract global IP address in " +
              succ_conns + " attempts");
        return Test.TEST_ERROR | Test.TEST_ERROR_IO_WRONGDATA;
        }
        
        Debug.debug("Successfully connected " + succ_conns + " of " +
          num_conns + " times to " + tcpServer + ":" + tcpPort);            
        //Debug.debug("Now attempting to walk the interface list");

        // We are using JDK 1.4 as minimum requirement,
        // which means we can't get the MAC address, but
        // we can get the IP addresses for the interfaces.
        //
        // Note, getHostAddress() may include a
        // %-separated zone identifier as per RFC 4007.

        try {
        Enumeration e = NetworkInterface.getNetworkInterfaces();

        while (e.hasMoreElements()) {
            NetworkInterface n = 
            (NetworkInterface) e.nextElement();
            //Debug.debug("Display name: " + n.getName());

            interfaceAddrs += Utils.safeUrlEncode(n.getName(), "UTF-8");
            interfaceAddrsHostname += 
                    Utils.safeUrlEncode(n.getName(), "UTF-8");
            
            Enumeration f = n.getInetAddresses();
            while (f.hasMoreElements()) {
            InetAddress g = (InetAddress) f.nextElement();
            String gAddr = g.getHostAddress();
            String gName = g.getHostName();
            interfaceAddrs += '!' + gAddr;
            interfaceAddrsHostname += '!' + gAddr + '^' + gName;
            //Debug.debug(" IP: " + gAddr);
            //Debug.debug(" hostname: " + gName);
            }

            if(e.hasMoreElements()){
            interfaceAddrs += ",";
            interfaceAddrsHostname += ",";
            }
        }
        // Uncomment to test for checking for
        // private 6to4 addrs
        // interfaceAddrs += ",tst!2002:0a00:2141::2";
        // Uncomment to test for checking for
        // rogue v6 routers
        // interfaceAddrs += ",tst!2002:2a00:2141::2!2002:2b00:2141::2";
        
        } catch (Exception e){
        Debug.debug("Caught exception " + e);
        }


        return Test.TEST_SUCCESS;
    }
    
    public String getPostResults() {
        String la = "";
        Iterator iter = localAddrs.iterator();
        while (iter.hasNext()) {
        la += iter.next();
        if (iter.hasNext())
            la += ",";
        }

        // Bugfix for Christian's reporting, if global
        // client addr can't be gotten, use the
        // globalHTTPAddr
        if (TestState.globalClientAddr.equals("0.0.0.0")) {
        return "globalAddr=" + TestState.globalHTTPAddr +
            "\nlocalAddr=" + la +
            "\ninterfaceAddrs=" + interfaceAddrs + // imported
            "\ninterfaceAddrsHostname=" +  // imported
            interfaceAddrsHostname + 
            "\nlocalPorts=" + localPorts + // imported 
            "\nglobalPorts=" + globalPorts + "\n"; // imported
        }

        return "globalAddr=" + TestState.globalClientAddr +
        "\nlocalAddr=" + la + 
        "\ninterfaceAddrs=" + interfaceAddrs + // imported
        "\ninterfaceAddrsHostname=" + // imported
        interfaceAddrsHostname + 
        "\nlocalPorts=" + localPorts + // imported
        "\nglobalPorts=" + globalPorts + "\n"; // imported
    }
}
