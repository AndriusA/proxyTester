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
        
        // try {
        //     t.start();
        //     synchronized(t) {
        //         t.wait();
        //     }
        // } catch (InterruptedException e) {
        //     Log.e(TAG, "Tester thread interrupted", e);
        // }
    }
}
