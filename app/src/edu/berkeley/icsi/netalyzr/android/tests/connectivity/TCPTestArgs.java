package edu.berkeley.icsi.netalyzr.tests.connectivity;

public class TCPTestArgs {

    // This class encapsulates parameters and results for the TCP
    // reachability test performed by the checkTCP function.

    // Parameters for the test
    // ---------------------------
    // timeout for connection attempt, default 15s
    public int timeoutMilliSecs;

    // number of bytes to be read
    public int todoData;

    // test received data against this string, if given
    public String expectedData;

    // Results of the test
    // ---------------------------
    // received data, assuming todoData > 0
    public String recvData;

    // local IP address and port for connection
    public String localAddr;
    public int localPort;

    // Remote address
    public String remoteAddr;

    // If this connection should not be timed
    public boolean do_not_time;

    public TCPTestArgs() {
        this.timeoutMilliSecs = 12000;
        this.todoData = 0;
        this.expectedData = this.recvData = null;
    }

    public TCPTestArgs(int todoData) {
        this.timeoutMilliSecs = 12000;
        this.todoData = todoData;
        this.expectedData = this.recvData = null;
    }

    public TCPTestArgs(int timeoutSecs, String expectedData) {
        this.timeoutMilliSecs = timeoutSecs * 1000;
        this.expectedData = expectedData;
        this.todoData = 0;
        if (this.expectedData != null)
            this.todoData = this.expectedData.length();
    }
}