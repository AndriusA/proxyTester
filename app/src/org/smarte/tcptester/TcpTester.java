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

import android.view.MenuInflater;
import android.view.View;
import android.support.v7.app.ActionBarActivity;
import android.support.v7.app.ActionBar;
import android.util.Log;
import android.content.Intent;
import android.view.MenuItem;
import android.widget.ImageButton;
import android.view.Menu;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.os.Bundle;
import org.smarte.tcptester.R;
import java.util.concurrent.ExecutionException;

import org.smarte.tcptester.engine.RawSocketTester;
import org.smarte.tcptester.engine.NetalyzrTester;

public class TcpTester extends ActionBarActivity implements View.OnClickListener 
{
    public static final String TAG = "TCPTester";
    private ProgressBar mProgress;
    private TextView mProgressText;

    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.form);
        int buttonId = R.id.connect;
        ImageButton btn = (ImageButton) findViewById(buttonId);
        mProgress = (ProgressBar)findViewById(R.id.testProgress);
        mProgressText = (TextView)findViewById(R.id.progressText);
        btn.setOnClickListener(this);

        ActionBar actionBar = getSupportActionBar();
        actionBar.setDisplayHomeAsUpEnabled(true);
        actionBar.show();
    }

    @Override
    public void onClick(View v) {
        NetalyzrTester netalyzrTester = new NetalyzrTester();
        netalyzrTester.execute();
        try {
            netalyzrTester.get();
            new RawSocketTester(this, mProgress, mProgressText).execute();
        } catch (ExecutionException e) {
            Log.e(TAG, "Tests did not finish, exception ", e);
        } catch (InterruptedException e) {
            Log.e(TAG, "Tests did not finish, interrupted ", e);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu items for use in the action bar
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.layout.main_activity_actions, menu);
        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle presses on the action bar items
        switch (item.getItemId()) {
            case R.id.action_about:
                openAbout();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void openAbout() {
        Intent intent = new Intent(this, TcpTesterAbout.class);
        startActivity(intent);
    }
    
}
