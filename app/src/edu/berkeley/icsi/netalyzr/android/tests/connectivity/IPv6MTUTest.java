package edu.berkeley.icsi.netalyzr.tests.connectivity;

import java.io.IOException;

import edu.berkeley.icsi.netalyzr.localization.Localization;
import edu.berkeley.icsi.netalyzr.tests.Debug;
import edu.berkeley.icsi.netalyzr.tests.Test;
import edu.berkeley.icsi.netalyzr.tests.TestState;
import edu.berkeley.icsi.netalyzr.tests.Utils;

public class IPv6MTUTest extends Test {

    public IPv6MTUTest(String name) {
        super(name);
    }

    int sendMTU;
    int recvMTU;

    String pathMTUProblem;
    String bottleneckIP;
    
    String v6SendFragments;
    String v6ReceiveFragments;

    public void init(){
        idleMsg = Localization.getLocalString(testName);
        pathMTUProblem = "false";
        bottleneckIP = "";
        v6SendFragments = "";
        v6ReceiveFragments = "";
    }
    
    public int runImpl() throws IOException {
        int port = Utils.parseInt(TestState.shell.getParameter("FRAGMENT_ECHO_PORT_V6"));
        int bufferPort = Utils.parseInt(TestState.shell.getParameter("UDP_BUFFER_PORT"));
        String udpServer = "ipv6-node." + TestState.custDnsName;
        UDPTestArgs udpArgs, bigUDPSend;


        if(!TestState.canDoRawUDP || !TestState.canDoV6){
        ignoreResult = true;
        return Test.TEST_PROHIBITED;
        }

        // sendMTU of -1 means the test didn't work at all
        sendMTU = -1;

        pathMTUProblem = "False";

        String message = "000.000 1 0 ";
        for (; message.length() < 2000;){
        message += ".";
        }
        v6SendFragments = "False";
        Debug.debug("Testing the ability to send a large UDP packet (2000 bytes) over IPv6");
        bigUDPSend = 
        new UDPTestArgs(1, 10, message.getBytes());
        // do a dummy to make sure the path is clear, I'm getting
        // ICMP too big type errors on the ethernet!
        UDPUtils.checkUDP(udpServer, bufferPort, bigUDPSend);
        if(UDPUtils.checkUDP(udpServer, bufferPort, bigUDPSend) 
           == Test.TEST_SUCCESS){
        Debug.debug("Can send UDP fragments successfully");
        v6SendFragments = "True";
        }
        else {
        Debug.debug("Can't send UDP fragments");
        pathMTUProblem = "True";
        }

        message = "000.000 2 2000 .";
        v6ReceiveFragments = "False";
        Debug.debug("Testing the ability to receive a large UDP packet (2000 bytes) over IPv6");
        bigUDPSend = 
        new UDPTestArgs(1, 10, message.getBytes());
        if(UDPUtils.checkUDP(udpServer, bufferPort, bigUDPSend) 
           == Test.TEST_SUCCESS){
        Debug.debug("Can receive UDP fragments successfully");
        v6ReceiveFragments = "True";
        }
        else {
        Debug.debug("Can't receive UDP fragments");
        pathMTUProblem = "True";
        }


        String msg = "fragment ";
        for(int i = 0; i < 200; ++i){
        msg += "1234567890";
        }

        Debug.debug("Attempting to send a packet with");
        Debug.debug("fragmentation of " + msg.length() + " bytes");
        udpArgs = new UDPTestArgs(1,10, msg.getBytes());
        byte [] fragmentData = UDPUtils.getUDPData(udpServer, port, udpArgs);
        if(fragmentData != null){
        Debug.debug("Got a reply back, so working");
        sendMTU = Utils.parseInt(new String(fragmentData));
        Debug.debug("Send packet MTU is " + sendMTU);
        } else {
        Debug.debug("No reply back");
        }

        TestState.v6SendMTU = sendMTU;

        Debug.debug("Now looking for the receive MTU. Trying 1500 first");
        msg = "mtu 1500 64";
        Debug.debug("MSG: " + msg);
        udpArgs = new UDPTestArgs(1,10, msg.getBytes());

        fragmentData = UDPUtils.getUDPData(udpServer, port, udpArgs);


        if(fragmentData == null){
        Debug.debug("No data received, so a potential path MTU problem");
        pathMTUProblem = "True";
        } else if((new String(fragmentData).startsWith("bad"))){
        Debug.debug("Response is " + new String(fragmentData));
        Debug.debug("Path MTU is <1500B");
        bottleneckIP = (new String(fragmentData)).split(" ")[2];
        } else {
        Debug.debug("Path MTU is >= 1500B");
        recvMTU = 1500;

        return TEST_SUCCESS;
        }

        Debug.debug("Beginning binary search to find the path MTU");

        int works = 0;
        int fails = 1500;
        int at = (fails - works) / 2 + works;

        while(works < (fails - 1)){
        Debug.debug("Works: " + works);
        Debug.debug("Fails: " + fails);
        Debug.debug("At:    " + at);

        msg = "mtu " + at + " 64";
        Debug.debug("Message: " + msg);

        udpArgs = new UDPTestArgs(1,5, msg.getBytes());
        fragmentData = 
            UDPUtils.getUDPData(udpServer, port, udpArgs);
        if(fragmentData == null){
            fails = at;
            Debug.debug("Silent failure");
        } else if((new String(fragmentData).startsWith("bad"))){
            fails = at;
            Debug.debug("Responsive failure");
            Debug.debug("Response is " + new String(fragmentData));
            bottleneckIP = (new String(fragmentData)).split(" ")[2];
        } else{
            Debug.debug("Success");
            works = at;
        }
        at = (fails - works) / 2 + works;
        }
        recvMTU = works;
        Debug.debug("Final MTU is " + recvMTU);

        // Uncomment for testing
        // pathMTUProblem = "True";
        // v6SendFragments = "False";
        // v6ReceiveFragments = "False";

        // Unncomment for testing
        // pathMTUProblem = "True";
        // bottleneckIP = "";

        return TEST_SUCCESS;
    }

    public String getPostResults() {
        return "\nsendPathMTUV6=" + sendMTU + // imported
        "\nrecvPathMTUV6=" + recvMTU + // imported
        "\npathMTUProblemV6=" + pathMTUProblem + // imported
        "\nbottleneckIPV6=" + bottleneckIP + // imported
        "\nv6SendFragments=" + v6SendFragments +  // imported
        "\nv6ReceiveFragments=" + v6ReceiveFragments + // imported
        "\n";
    }       
}
