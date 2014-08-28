package edu.berkeley.icsi.netalyzr.tests.connectivity;

import edu.berkeley.icsi.netalyzr.tests.Debug;

public class UDPTestArgs {

    // This class encapsulates parameters and results for the UDP
    // reachability test performed by the checkUDP function.

    // Parameters for the test
    // ---------------------------
    // timeout for connection attempt
    public int timeoutMilliSecs;

    // Number of datagrams to send
    public int numSend;

    // Results of the test
    // ---------------------------
    // number of datagrams received
    public int numRecv;

    // received datagram lengths, -1 used on error
    public int recvLen[];

    // local IP address and port for connection
    public String localAddrs[];
    public int localPorts[];

    // Payload for sending; we don't currently record the received
    // payload.
    public byte payload[];

    public long sendPacketTS;
    public long recvPacketTS;

    public UDPTestArgs() {
        timeoutMilliSecs = 1500; // (used to be 5 secs)
        numSend = 10;
        numRecv = 0;
        recvLen = new int[numSend];
        localAddrs = new String[numSend];
        localPorts = new int[numSend];
        this.payload = null;
    }

    public UDPTestArgs(int timeoutSecs, int numSend) {
        timeoutMilliSecs = timeoutSecs * 1000;
        this.numSend = numSend;
        numRecv = 0;
        recvLen = new int[numSend];
        localAddrs = new String[numSend];
        localPorts = new int[numSend];
        this.payload = null;
    }

    public UDPTestArgs(int timeoutSecs, int numSend, byte[] payload) {
        timeoutMilliSecs = timeoutSecs * 1000;
        this.numSend = numSend;
        this.payload = payload;
        numRecv = 0;
        recvLen = new int[numSend];
        localAddrs = new String[numSend];
        localPorts = new int[numSend];
    }

    public void debugStatus() {
        Debug.debug("UDP arguments");
        Debug.debug("numSend: " + numSend);
        Debug.debug("numRecv: " + numRecv);
        Debug.debug("payload: " + new String(payload));
    }

    public void addResult(String localAddr, int localPort, int len) {
        if (numRecv >= numSend)
            return;

        localAddrs[numRecv] = localAddr;
        localPorts[numRecv] = localPort;
        recvLen[numRecv] = len;
        numRecv++;
    }
}
