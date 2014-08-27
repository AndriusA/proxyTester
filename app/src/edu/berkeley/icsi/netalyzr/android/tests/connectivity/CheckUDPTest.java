package edu.berkeley.icsi.netalyzr.tests.connectivity;

import java.io.IOException;

import edu.berkeley.icsi.netalyzr.localization.Localization;
import edu.berkeley.icsi.netalyzr.tests.Debug;
import edu.berkeley.icsi.netalyzr.tests.Test;
import edu.berkeley.icsi.netalyzr.tests.TestState;
import edu.berkeley.icsi.netalyzr.tests.Utils;

public class CheckUDPTest extends Test {


    public CheckUDPTest(String name) {
        super(name);
    }
    UDPTestArgs udpArgs;
    String largeUDPSend;
    String largeUDPRecv;
    int largeUDPRecvMTU;
    int largeUDPSendMTU;
    
    String largeUDPSend1471;
    String largeUDPRecv1471;

    public void init() { 
        idleMsg = Localization.getLocalString(testName);
        udpArgs = new UDPTestArgs();
        largeUDPSend = "False";
        largeUDPRecv = "False";
        largeUDPSend1471 = "False";
        largeUDPRecv1471 = "True";
    }

    public int runImpl() throws IOException {
        String udpServer = TestState.serverName;
        // shell.getParameter("ECHO_SERVER");
        int port = Utils.parseInt(TestState.shell.getParameter("UDP_ECHO_PORT"));
        int retval = UDPUtils.checkUDP(udpServer, port, udpArgs);
        if(retval == Test.TEST_SUCCESS){
        Debug.debug("Can perform raw UDP access");
        TestState.canDoRawUDP = true;
        } else {
        Debug.debug("Can not perform raw UDP access");
        }
        if(TestState.canDoRawUDP){

        // Now we check whether the system can
        // handle fragmented UDP traffic for sending

        // We just basically send a message to our ping
        // server with a lot of padding with a return size
        // which is small
        String message = "000.000 1 0 ";

        int bufferPort = Utils.parseInt(TestState.shell.getParameter("UDP_BUFFER_PORT"));

        UDPTestArgs bigUDPSend;
        UDPTestArgs bigUDPRecv;

        message = "000.000 1 0 ";
        for (; message.length() < 1471;){
            message += ".";
        }
        Debug.debug("Testing the ability to send a 1471B UDP packet");
        bigUDPSend =
            new UDPTestArgs(1, 10, message.getBytes());
        
        if(UDPUtils.checkUDP(udpServer, bufferPort, bigUDPSend)
           == Test.TEST_SUCCESS){
            Debug.debug("Can send a 1471B UDP packet");
            largeUDPSend1471 = "True";
        } else {
            Debug.debug("Unable to send a 1471B UDP packet");
            Debug.debug("So trying once more");
            bigUDPSend =
            new UDPTestArgs(1, 10, message.getBytes());
            if(UDPUtils.checkUDP(udpServer, bufferPort, bigUDPSend)
               == Test.TEST_SUCCESS){
            Debug.debug("Able to go the second time");
            largeUDPSend1471 = "Linux";
            } else {
            Debug.debug("Full send MTU hole");
            
            }
        }

        // Uncomment for testing
        // largeUDPSend1471 = "Linux";


        message = "000.000 1 0 ";
        for (; message.length() < 2000;){
            message += ".";
        }

        Debug.debug("Testing the ability to send a large UDP packet (2000 bytes)");
        bigUDPSend = 
            new UDPTestArgs(1, 10, message.getBytes());

        // Just in case we get a too-big on the first
        // try, do a pretry
        UDPUtils.checkUDP(udpServer, bufferPort, bigUDPSend) ;
        if(UDPUtils.checkUDP(udpServer, bufferPort, bigUDPSend) 
           == Test.TEST_SUCCESS){
            Debug.debug("Can send UDP fragments successfully");
            largeUDPSend = "True";
            largeUDPSendMTU = 2000;
            TestState.canSendFragmentedUDP = true;
        } else{
            idleMsg = Localization.getLocalString("checkUDPMTU");
            try {
                TestState.shell.enableRedraw();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            timeout = 30000;

            Debug.debug("Can not successfully send UDP fragments");
            Debug.debug("Trying to discover maximum MTU");
            int works = 0;
            int fails = 2000;
            int at = 1000;
            while(works < (fails - 1)){
            Debug.debug("Works: " + works);
            Debug.debug("Fails: " + fails);
            Debug.debug("At:    " + at);
            message = "000.000 1 0 ";
            for(; message.length() < at; ){
                message += ".";
            }
            bigUDPSend = 
                new UDPTestArgs(1, 5, message.getBytes());
            if(UDPUtils.checkUDP(udpServer, bufferPort, bigUDPSend) 
               == Test.TEST_SUCCESS){
                works = at;
                Debug.debug("Able to get the packet");
            }
            else {
                Debug.debug("Not able to get the reply");
                fails = at;
            }
            at = (fails - works) / 2 + works;
            }
            Debug.debug("Found maximum working value " + works);
            Debug.debug("Failure at " + fails);
            largeUDPSendMTU = works;
        }


        Debug.debug("Testing the ability to receive a 1471B UDP");
        Debug.debug("reply from our server");
        
        message = "000.000 0 1471";
        bigUDPRecv = 
            new UDPTestArgs(1, 10, message.getBytes());
        
        if(UDPUtils.checkUDP(udpServer, bufferPort, bigUDPRecv)
           == Test.TEST_SUCCESS){
            Debug.debug("Can receive a 1471B UDP packet");
            largeUDPRecv1471 = "True";
        } else {
            Debug.debug("Unable to receive a 1471B UDP packet");
        }


        Debug.debug("Testing the ability to receive a large UDP packet (2000 bytes)");

        message = "000.000 0 2000";
        bigUDPRecv = 
            new UDPTestArgs(1, 5, message.getBytes());
        if(UDPUtils.checkUDP(udpServer, bufferPort, bigUDPRecv) 
           == Test.TEST_SUCCESS){
            Debug.debug("Can receive UDP fragments successfully");
            largeUDPRecv = "True";
            largeUDPRecvMTU = 2000;
        } else{
            idleMsg = Localization.getLocalString("checkUDPFragMTU");
            try {
                TestState.shell.enableRedraw();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            timeout = 30000;

            Debug.debug("Can not successfully receive large UDP");
            Debug.debug("Trying to discover practical UDP MTU");
            int works = 0;
            int fails = 1999;
            int at = 1000;
            while(works < (fails - 1)){
            Debug.debug("Works: " + works);
            Debug.debug("Fails: " + fails);
            Debug.debug("At:    " + at);
            message = "000.000 0 " + at;
            bigUDPRecv = 
                new UDPTestArgs(1, 10, message.getBytes());
            if(UDPUtils.checkUDP(udpServer, bufferPort, bigUDPRecv) 
               == Test.TEST_SUCCESS){
                works = at;
                Debug.debug("Able to get the packet");
            }
            else {
                Debug.debug("Not able to get the reply");
                fails = at;
            }
            at = (fails - works) / 2 + works;
            }
            Debug.debug("Found maximum working value " + works);
            Debug.debug("Failure at " + fails);
            largeUDPRecvMTU = works;
        }
        }

        return retval;
    }

    public String getPostResults() {
        if (udpArgs.numRecv == 0)
        return "";

        String la = "";
        String lp = "";

        for (int i = 0; i < udpArgs.numRecv; i++) {
        la += udpArgs.localAddrs[i];
        lp += Integer.toString(udpArgs.localPorts[i]);

        if (i < udpArgs.numRecv - 1) {
            la += ",";
            lp += ",";
        }
        }
        
        return "localUDPAddrs=" + la +
        "\nlocalUDPPorts=" + lp + // imported
        "\nlargeUDPSend=" + largeUDPSend + // imported
        "\nlargeUDPRecv=" + largeUDPRecv + // imported
        "\nlargeUDPRecvMTU=" + largeUDPRecvMTU + // imported
        "\nlargeUDPSendMTU=" + largeUDPSendMTU + // imported
        "\nlargeUDPRecv1471=" + largeUDPRecv1471 + // imported
        "\nlargeUDPSend1471=" + largeUDPSend1471 + // imported
        "\n";
    }
}
