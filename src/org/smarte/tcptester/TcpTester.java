package org.smarte.tcptester;

import android.app.Activity;
import android.widget.TextView;
import android.widget.Button;
import android.view.View;
import android.os.Bundle;
import android.content.Intent;
import android.content.Context;
import android.net.VpnService;
import android.net.NetworkInfo;
import android.net.ConnectivityManager;
import android.util.Log;
import android.os.Build;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import com.stericson.RootTools.RootTools;

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
        new RawSocketTester(TcpTester.this).execute(mServerAddress.getText().toString(), mServerPort.getText().toString());
    }
}
