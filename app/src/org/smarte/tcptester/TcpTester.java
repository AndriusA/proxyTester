/*
 * Copyright (c) 2014 Andrius Aucinas <andrius.aucinas@cl.cam.ac.uk>
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package org.smarte.tcptester;

import android.app.Activity;
import android.widget.TextView;
import android.os.Bundle;
import android.view.View;
import android.util.Log;
import org.apache.http.client.methods.HttpPost;
import java.util.ArrayList;
import org.apache.http.NameValuePair;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.client.ResponseHandler;
import java.util.List;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.HttpResponse;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import android.widget.ImageButton;
import android.widget.ProgressBar;
import android.os.AsyncTask;


import edu.berkeley.icsi.netalyzr.tests.Test;

public class TcpTester extends Activity implements View.OnClickListener 
{
    public static final String TAG = "TCPTester";
    private ProgressBar mProgress;
    private TextView mProgressText, mSubmittedResults;

    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.form);
        int buttonId = R.id.connect;
        ImageButton btn = (ImageButton) findViewById(buttonId);
        mProgress = (ProgressBar)findViewById(R.id.testProgress);
        mProgressText = (TextView)findViewById(R.id.progressText);
        mSubmittedResults = (TextView)findViewById(R.id.submittedResults);
        btn.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        new RawSocketTester(getApplicationContext(), mProgress, mProgressText, mSubmittedResults).execute();

        // tcpTester.init();
        // Thread t = new Thread(tcpTester);
        // t.start();

        // try {
        //     synchronized(tcpTester) {
        //         if (tcpTester.getTestResultCode() == Test.TEST_NOT_EXECUTED) {
        //             Log.d(TAG, "Waiting for the test to finish");
        //             tcpTester.wait();
        //         }
        //     }
        // } catch (InterruptedException e) {
        //     Log.e(TAG, "Tester thread interrupted", e);
        // }
    }

    
}
