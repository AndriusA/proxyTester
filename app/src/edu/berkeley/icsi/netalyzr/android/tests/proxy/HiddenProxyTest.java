package edu.berkeley.icsi.netalyzr.tests.proxy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Date;

import edu.berkeley.icsi.netalyzr.localization.Localization;
import edu.berkeley.icsi.netalyzr.tests.Debug;
import edu.berkeley.icsi.netalyzr.tests.Test;
import edu.berkeley.icsi.netalyzr.tests.TestState;

public class HiddenProxyTest extends Test {
    
    StringBuffer proxiedPorts = new StringBuffer();
    StringBuffer unproxiedPorts = new StringBuffer();
    InetAddress nonResponsiveIP;
    
    public HiddenProxyTest(String name) {
        super(name);
    }
    
    public void init() { 
        this.idleMsg = Localization.getLocalString(this.testName);
    }

    public int runImpl() throws IOException {
        if (!TestState.canDoUnrestrictedLookup){
        return Test.TEST_NOT_EXECUTED;
        }

        String nonResponsiveName = 
        "nonresponsive." + TestState.custDnsName;
        nonResponsiveIP =
        InetAddress.getByName(nonResponsiveName);           
        Debug.debug("Nonresponsive name/IP address is " + 
          nonResponsiveName + "/" +
          nonResponsiveIP);

        for (int i = 0; i < TestState.proxyPortsToTest.length; ++i) {
        Debug.debug("Attempting to check port " + 
                TestState.proxyPortsToTest[i]);
        try {
            InetSocketAddress addr = 
            new InetSocketAddress(nonResponsiveIP,
                    TestState.proxyPortsToTest[i]);
            Socket testConn = new Socket();
            long connectionTime = (new Date()).getTime();
            testConn.connect(addr, 500); // 500ms timeout
            connectionTime = (new Date()).getTime() - connectionTime;
            Debug.debug("connected to '" + addr + "' in " 
              + connectionTime + " ms");
            if (proxiedPorts.length() > 0)
            proxiedPorts.append(",");
            proxiedPorts.append(TestState.proxyPortsToTest[i]);
            proxiedPorts.append("/" + connectionTime);

            // We found a proxy on this port, so let's
            // include it in the list of ports our
            // SYN-ACK traceroute will test in order
            // to determine the proxy's location:
            TestState.tracebackProxyPorts.add(new Integer(TestState.proxyPortsToTest[i]));

            try {
            testConn.close();
            } catch (Exception e){
            Debug.debug("Caught exception on closing " + e);
            }
        }
        catch (Exception e) {
            Debug.debug("Connection failed: " + e);
            if (unproxiedPorts.length() > 0)
            unproxiedPorts.append(",");
            unproxiedPorts.append(TestState.proxyPortsToTest[i]);
        }
        }
        
        return Test.TEST_SUCCESS;
    }

    public String getPostResults(){
        // for testing of rendering
        // return "\ncheckedPortsWithProxies=" + "21/66,22/66,80/66,443/66" +
        return "\ncheckedPortsWithProxies=" + proxiedPorts + // imported 
        "\ncheckedPortsWithoutProxies=" + unproxiedPorts +  // imported
        "\ncheckedNonResponsiveIP=" + nonResponsiveIP + "\n"; // imported
    }
    
}
