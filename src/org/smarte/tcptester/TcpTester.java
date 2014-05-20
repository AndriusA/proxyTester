package org.smarte.tcptester;

import android.app.Activity;
import android.widget.TextView;
import android.os.Bundle;
import android.view.View;

import edu.berkeley.icsi.netalyzr.tests.Test;

public class TcpTester extends Activity implements View.OnClickListener 
{
    public static final String TAG = "TCPTester";
    private static final String PREFS_NAME = TAG;
    private static final String TESTER_BINARY = "tcptester";
    private static final String D_SERVER = "192.95.61.160";
    private static final String D_PORT = "6969";

    private TextView mServerAddress;
    private TextView mServerPort;
    private TextView mSharedSecret;

    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.form);
        mServerAddress = (TextView) findViewById(R.id.address);
        mServerPort = (TextView) findViewById(R.id.port);
        findViewById(R.id.connect).setOnClickListener(this);

        mServerAddress.setText(D_SERVER);
        mServerPort.setText(D_PORT);
    }

    @Override
    public void onClick(View v) {
        Test tcpTester = new RawSocketTester("TCPTester", getApplicationContext());
        tcpTester.init();
        new Thread(tcpTester).start();
    }
}
