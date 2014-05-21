package org.smarte.tcptester;

import android.app.Activity;
import android.widget.TextView;
import android.os.Bundle;
import android.view.View;

import edu.berkeley.icsi.netalyzr.tests.Test;

public class TcpTester extends Activity implements View.OnClickListener 
{
    public static final String TAG = "TCPTester";

    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.form);
        findViewById(R.id.connect).setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        Test tcpTester = new RawSocketTester("TCPTester", getApplicationContext());
        tcpTester.init();
        new Thread(tcpTester).start();
    }
}
