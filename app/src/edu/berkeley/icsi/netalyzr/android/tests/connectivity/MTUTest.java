package edu.berkeley.icsi.netalyzr.tests.connectivity;

import java.io.IOException;

import edu.berkeley.icsi.netalyzr.localization.Localization;
import edu.berkeley.icsi.netalyzr.tests.Debug;
import edu.berkeley.icsi.netalyzr.tests.Test;
import edu.berkeley.icsi.netalyzr.tests.TestState;
import edu.berkeley.icsi.netalyzr.tests.Utils;

public class MTUTest extends Test {

    public MTUTest(String name) {
        super(name);
    }
    
    int sendMTU;
    int recvMTU;

    String pathMTUProblem;
    String bottleneckIP;
    
    public void init(){
        idleMsg = Localization.getLocalString(testName);
        pathMTUProblem = "false";
        bottleneckIP = "";
    }
    
    public int runImpl() throws IOException {
        int port = Utils.parseInt(TestState.shell.getParameter("FRAGMENT_ECHO_PORT"));
        String udpServer = TestState.serverName;
        UDPTestArgs udpArgs;

        if(!TestState.canDoRawUDP){
        ignoreResult = true;
        return Test.TEST_PROHIBITED;
        }

        // sendMTU of -1 means the test didn't work at all
        sendMTU = -1;
        
        String msg = "fragment ";
        for(int i = 0; i < 200; ++i){
        msg += "1234567890";
        }

        Debug.debug("Attempting to send a packet with");
        Debug.debug("fragmentation of " + msg.length() + " bytes");
        udpArgs = new UDPTestArgs(1,10, msg.getBytes());
        byte [] fragmentData = 
        UDPUtils.getUDPData(udpServer, port, udpArgs);
        if(fragmentData != null){
        Debug.debug("Got a reply back, so working");
        sendMTU = Utils.parseInt(new String(fragmentData));
        Debug.debug("Send packet MTU is " + sendMTU);
        } else {
        Debug.debug("No reply back");
        }

        Debug.debug("Now looking for the receive MTU. Trying 1500 first");
        msg = "mtu 1500 64";
        Debug.debug("MSG: " + msg);
        udpArgs = new UDPTestArgs(1,10, msg.getBytes());

        fragmentData = UDPUtils.getUDPData(udpServer, port, udpArgs);

        pathMTUProblem = "False";

        if(fragmentData == null){
        Debug.debug("No data received, so a path MTU problem");
        pathMTUProblem = "True";
        } else if((new String(fragmentData).startsWith("bad"))){
        Debug.debug("Response is " + new String(fragmentData));
        Debug.debug("Path MTU is <1500B");
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
        fragmentData = UDPUtils.getUDPData(udpServer, port, udpArgs);
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
        return TEST_SUCCESS;

    }
    
    public String getPostResults() {
        return "\nsendPathMTU=" + sendMTU + // imported
        "\nrecvPathMTU=" + recvMTU + // imported
        "\npathMTUProblem=" + pathMTUProblem + // imported
        "\nbottleneckIP=" + bottleneckIP + // imported
        "\n";
    }

}
