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
import android.location.LocationManager;
import android.location.Location;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;

import edu.berkeley.icsi.netalyzr.tests.Test;
import org.smarte.tcptester.R;
import org.smarte.tcptester.TcpTesterResults;
import org.smarte.tcptester.TcpTester;

public class TestEngine extends AsyncTask<Void, Integer, Integer>
{
    public static final String TAG = TcpTester.TAG;

    public static final int TEST_COMPLETED = 101;
    public static final int TESTSUITE_COMPLETED = 102;
    public static final int TESTSUITE_ERROR_PROHIBITED = 105;
    public static final int TESTSUITE_ERROR_NETWORK = 106;
    public static final int TESTSUITE_ERROR_OTHER = 169;

	public static final String TestServer = "192.95.61.161";
	public static final Integer TestPorts[] = new Integer[]{80, 443, 993, 8000, 5228, 6969};

    private Context mActivity;
    private ProgressBar mProgress;
    private TextView mProgressText, mSubmittedResults;
    private ArrayList<TCPTest> mResults;

    ProgressCallbackInterface mCallback;
    Handler mHandler;

	public TestEngine(Activity activity, ProgressBar progress, TextView progressText) {
        super();
        mActivity = activity;
        mProgress = progress;
        mProgressText = progressText;

        mHandler = new Handler(Looper.getMainLooper()) {
            /*
             * handleMessage() defines the operations to perform when the
             * Handler receives a new Message to process.
             */
            @Override
            public void handleMessage(Message inputMessage) {
                /*
                 * Chooses the action to take, based on the incoming message
                 */
                switch (inputMessage.what) {
                    // If the test has finished with a TEST_COMPLEX state
                    case TestEngine.TESTSUITE_COMPLETED:
                        Log.d(TAG, "Testsuite completed");
                        // inputMessage.obj should contain the results of a testsuite completed
                        try {
                            mResults.addAll((ArrayList<TCPTest>)inputMessage.obj);
                        } catch (Exception e) {
                            Log.e(TAG, "Failed to retrieve results from some testsuite; ignoring.");
                        }
                        break;
                    case TestEngine.TEST_COMPLETED:
                        Log.d(TAG, "Test in a testsuite completed");
                        publishProgress(1);
                        break;
                }
            }
        };
    }

    protected Integer doInBackground(Void... none) {
        NetalyzrTester netalyzrTester = new NetalyzrTester(mHandler, TestPorts);
        Log.d(TAG, "Launch Netalyzr tests");
        
        new Thread(netalyzrTester).start();
        getCoarseLocation();
        Log.d(TAG, "Waiting for Netalyzr tets to finish");
        synchronized (netalyzrTester) {
            if (!netalyzrTester.done) {
                try {
                    netalyzrTester.wait();
                } catch (InterruptedException e) {
                    // Returning with an error - need NetalyzrTets to 
                    // complete between running the next testsuite
                    return Test.TEST_ERROR_NOT_COMPLETED;
                }
            }
        }
        
        RawSocketTester rawSocketTester = new RawSocketTester(mActivity, mHandler, TestServer, TestPorts, netalyzrTester.localAddress);
        Log.d(TAG, "Launch RawSocketTester tests");
        new Thread(rawSocketTester).start();

        synchronized (rawSocketTester) {
            if (!rawSocketTester.done) {
                try {
                    rawSocketTester.wait();
                } catch (InterruptedException e) {
                    return Test.TEST_ERROR_NOT_COMPLETED;
                }
            }
        }
        
        return TestEngine.TESTSUITE_COMPLETED;
    }
    
    protected void onProgressUpdate(Integer... progress) {
         mProgress.incrementProgressBy(progress[0]);
         // mProgressText.setText("Running Tests: " + Integer.toString(progress[1]) + "/" + Integer.toString(progress[2]));
    }

    protected void onPostExecute(Integer result) {
        Log.d(TAG, "execution finished, launching resuls activity");
        super.onPostExecute(result);
        Intent intent = new Intent(mActivity, TcpTesterResults.class);
        if (result == TestEngine.TESTSUITE_COMPLETED) {
            intent.putExtra("status", "success");
        } else if (result == TestEngine.TESTSUITE_ERROR_PROHIBITED) {
            intent.putExtra("status", "prohibited");
        } else {
            intent.putExtra("status", "failed");
        }
        intent.putParcelableArrayListExtra("results", mResults);
        mActivity.startActivity(intent);
    }

    // //define callback interface
    public interface ProgressCallbackInterface {
        void onProgressUpdate(Integer... progress);
    }

    private void getCoarseLocation() {
        LocationManager locationManager = (LocationManager) mActivity.getSystemService(mActivity.LOCATION_SERVICE);
        String locationProvider = LocationManager.NETWORK_PROVIDER;
        // Or use LocationManager.GPS_PROVIDER
        Location lastKnownLocation = locationManager.getLastKnownLocation(locationProvider);
        double lat, lon;
        try {
            lat = lastKnownLocation.getLatitude();
            lon = lastKnownLocation.getLongitude();
        } catch (NullPointerException e) {
            lat = -1.0;
            lon = -1.0;
        }
        Log.d(TAG, "Last known location: " + Double.toString(lat) + ":" + Double.toString(lon));
        return;
    }
}