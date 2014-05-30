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


import edu.berkeley.icsi.netalyzr.tests.Test;

public class TcpTester extends Activity implements View.OnClickListener 
{
    public static final String TAG = "TCPTester";

    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.form);
        int buttonId = R.id.connect;
        View listener = findViewById(buttonId);
        listener.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        Test tcpTester = new RawSocketTester("TCPTester", getApplicationContext());
        tcpTester.init();
        Thread t = new Thread(tcpTester);
        t.start();

        try {
            synchronized(tcpTester) {
                if (tcpTester.getTestResultCode() == Test.TEST_NOT_EXECUTED) {
                    Log.d(TAG, "Waiting for the test to finish");
                    tcpTester.wait();
                }
            }
        } catch (InterruptedException e) {
            Log.e(TAG, "Tester thread interrupted", e);
        }

        Log.d(TAG, "Posting results");
        postDataHttp(tcpTester.getPostResults());
    }

    private void postDataHttp(String data) {
        DefaultHttpClient httpclient = new DefaultHttpClient();
        HttpPost httpost = new HttpPost("http://tcptester.smart-e.org/result");
        List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(2);
        nameValuePairs.add(new BasicNameValuePair("id", "12345"));
        nameValuePairs.add(new BasicNameValuePair("result", data));

        try {
            httpost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            //Handles what is returned from the page 
            ResponseHandler responseHandler = new BasicResponseHandler();
            httpclient.execute(httpost, responseHandler);
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "Error Post'ing", e);
        }  catch (IOException e) {
            Log.e(TAG, "Error Post'ing", e);
        }
    }
}
