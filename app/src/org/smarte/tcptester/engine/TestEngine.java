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

package org.smarte.tcptester.engine;

import android.os.Build;
import java.util.ArrayList;
import android.content.pm.PackageManager.NameNotFoundException;
import java.io.IOException;
import java.net.UnknownHostException;
import android.content.Intent;
import android.content.Context;
import java.util.concurrent.TimeoutException;
import android.app.Activity;
import android.widget.ProgressBar;
import android.os.AsyncTask;
import android.widget.TextView;
import android.net.NetworkInfo;
import java.util.List;
import android.content.pm.PackageManager;
import java.util.Random;
import android.content.pm.PackageInfo;
import java.net.SocketException;
import java.util.Enumeration;
import android.util.Log;
import android.net.ConnectivityManager;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Date;
import java.util.concurrent.ExecutionException;

import edu.berkeley.icsi.netalyzr.tests.Test;
import org.smarte.tcptester.R;
import org.smarte.tcptester.TcpTesterResults;
import org.smarte.tcptester.TcpTester;

public class TestEngine extends AsyncTask<Void, Integer, Integer>
{
    public static final String TAG = TcpTester.TAG;
	public static final String TestServer = "192.95.61.161";
	public static final Integer TestPorts[] = new Integer[]{80, 443, 993, 8000, 5228, 6969};

    private Context mActivity;
    private ProgressBar mProgress;
    private TextView mProgressText, mSubmittedResults;
    private ArrayList<TCPTest> mResults;

    ProgressCallbackInterface mCallback;

	public TestEngine(Activity activity, ProgressBar progress, TextView progressText) {
        super();
        mActivity = activity;
        mProgress = progress;
        mProgressText = progressText;

        mCallback = new ProgressCallbackInterface() {
            @Override
            public void onProgressUpdate(Integer... progress) {
                mProgress.incrementProgressBy(progress[0]);
                mProgressText.setText("Running Tests: " + Integer.toString(progress[1]) + "/" + Integer.toString(progress[2]));
            }
        };
    }

    protected Integer doInBackground(Void... none) {
        NetalyzrTester netalyzrTester = new NetalyzrTester(mCallback, TestPorts);
        netalyzrTester.execute();
        try {
            netalyzrTester.get();
            RawSocketTester rawSocketTester = new RawSocketTester(mCallback, TestServer, TestPorts, netalyzrTester.localAddress);
            rawSocketTester.execute();
            rawSocketTester.get();
        } catch (ExecutionException e) {
            Log.e(TAG, "Tests did not finish, exception ", e);
        } catch (InterruptedException e) {
            Log.e(TAG, "Tests did not finish, interrupted ", e);
        }
        return 0;
    }
    
    protected void onProgressUpdate(Integer... progress) {
         mProgress.incrementProgressBy(progress[0]);
         mProgressText.setText("Running Tests: " + Integer.toString(progress[1]) + "/" + Integer.toString(progress[2]));
    }

    protected void onPostExecute(Integer result) {
        Log.d(TAG, "execution finished, launching resuls activity");
        super.onPostExecute(result);
        Intent intent = new Intent(mActivity, TcpTesterResults.class);
        if (result == Test.TEST_COMPLEX) {
            intent.putExtra("status", "success");
        } else if (result == Test.TEST_PROHIBITED) {
            intent.putExtra("status", "prohibited");
        } else {
            intent.putExtra("status", "failed");
        }
        intent.putParcelableArrayListExtra("results", mResults);
        mActivity.startActivity(intent);
    }

    //define callback interface
    public interface ProgressCallbackInterface {
        void onProgressUpdate(Integer... progress);
    }
}