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
import java.io.UnsupportedEncodingException;
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
import android.os.Bundle;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.telephony.TelephonyManager;

import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.entity.StringEntity;

import edu.berkeley.icsi.netalyzr.tests.Test;
import org.smarte.tcptester.R;
import org.smarte.tcptester.TcpTesterResults;
import org.smarte.tcptester.TcpTester;

import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

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
    private ArrayList<TCPTest> mResults, netResults;
    private String mUUID;

    ProgressCallbackInterface mCallback;
    Handler mHandler;

	public TestEngine(Activity activity, ProgressBar progress, TextView progressText) {
        super();
        mActivity = activity;
        mProgress = progress;
        mProgressText = progressText;
        mResults = new ArrayList<TCPTest>();
        netResults = new ArrayList<TCPTest>();

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
                Bundle input = inputMessage.getData();
                switch (input.getInt("response")) {
                    // If the test has finished with a TEST_COMPLEX state
                    case TestEngine.TESTSUITE_COMPLETED:
                        Log.d(TAG, "Testsuite completed");
                        try {
                            ArrayList<TCPTest> results = input.getParcelableArrayList("results");
                            if (input.getInt("testsuite") == RawSocketTester.Testsuite_ID) {
                                mResults.addAll(results);
                            }
                            else {
                                netResults.addAll(results);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, "Failed to retrieve results from testsuite " + Integer.toString(input.getInt("testsuite")) + " ignoring.", e);
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
        Log.d(TAG, "Waiting for Netalyzr tets to finish");
        int ret = TestEngine.TESTSUITE_COMPLETED;
        synchronized (netalyzrTester) {
            if (!netalyzrTester.done) {
                try {
                    netalyzrTester.wait();
                } catch (InterruptedException e) {
                    /* 
                     * Returning with an error - need NetalyzrTets to 
                     * complete between running the next testsuite
                     */
                    ret = Test.TEST_ERROR_NOT_COMPLETED;
                    return ret;
                }
            }
        }
        
        mUUID = netalyzrTester.UUID;
        RawSocketTester rawSocketTester = new RawSocketTester(mActivity, mHandler, 
            TestServer, TestPorts, netalyzrTester.localAddress
        );
        Log.d(TAG, "Launch RawSocketTester tests");
        new Thread(rawSocketTester).start();

        synchronized (rawSocketTester) {
            if (!rawSocketTester.done) {
                try {
                    rawSocketTester.wait();
                } catch (InterruptedException e) {
                    ret = Test.TEST_ERROR_NOT_COMPLETED;
                }
            }
        }

        Log.i(TAG, "Posting results");
        postResults();

        return ret;
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

        for (TCPTest tres : mResults) {
            Log.d(TAG, tres.toJSON().toString());
        }

        intent.putParcelableArrayListExtra("results", mResults);
        mActivity.startActivity(intent);
    }

    // //define callback interface
    public interface ProgressCallbackInterface {
        void onProgressUpdate(Integer... progress);
    }


    String collectResults() {
        JSONObject location = getCoarseLocation();
        JSONObject networkInfo = getNetworkInfo();

        JSONObject result = new JSONObject();
        try {
            result.put("UUID", mUUID);
            result.put("location", location);
            result.put("networkInfo", networkInfo);
            JSONArray testResults = new JSONArray();
            for (TCPTest tres : mResults) {
                testResults.put(tres.toJSON());
            }
            for (TCPTest tres : netResults) {
                testResults.put(tres.toJSON());   
            }
            result.put("results", testResults);
            Log.d(TAG, result.toString());
        } catch (JSONException e) {
            Log.d(TestEngine.TAG, "Error buidling JSON for network info", e);
        }
        return result.toString();
    }

    boolean postResults() {
        DefaultHttpClient httpclient = new DefaultHttpClient();
        HttpPost httpost = new HttpPost("http://192.95.61.160:3000/data/");
        // HttpPost httpost = new HttpPost("");
        httpost.setHeader("Accept", "application/json");
        httpost.setHeader("Content-type", "application/json");

        try {
            StringEntity postResults = new StringEntity(collectResults());
            httpost.setEntity(postResults);
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "result encoding error", e);
            return false;
        }

        try {
            //Handles what is returned from the page 
            ResponseHandler responseHandler = new BasicResponseHandler();
            httpclient.execute(httpost, responseHandler);
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Error Post'ing", e);
            return false;
        } catch (Exception e) {
            Log.e(TAG, "Another error post'ing", e);
            return false;
        }
    }

    private JSONObject getCoarseLocation() {
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
        JSONObject result = new JSONObject();
        try {
            // Here we convert Java Object to JSON 
            result.put("name", "location"); // Set the first name/pair 
            result.put("latitude", lat);
            result.put("longitude", lon);
        }
        catch(JSONException e) {
            Log.d(TestEngine.TAG, "Error buidling JSON for location", e);
        }
        // Log.d(TAG, "Location: " + result.toString());
        return result;
    }

    private JSONObject getNetworkInfo() {
        ConnectivityManager connMgr = 
            (ConnectivityManager) mActivity.getSystemService(mActivity.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connMgr.getActiveNetworkInfo();

        JSONObject result = new JSONObject();
        try {
            result.put("networkInfo", networkInfo.toString());
            result.put("extra", networkInfo.getExtraInfo());
            result.put("type", networkInfo.getTypeName());
            result.put("subtype", networkInfo.getSubtypeName());
            result.put("roaming", networkInfo.isRoaming());

            if (networkInfo.getType() == ConnectivityManager.TYPE_WIFI) {
                WifiManager wifiManager = (WifiManager) mActivity.getSystemService(mActivity.WIFI_SERVICE);
                WifiInfo info = wifiManager.getConnectionInfo();
                result.put("wifi", info.toString());
                result.put("SSID", info.getSSID());
            } else {
                TelephonyManager telephonyManager = (TelephonyManager) mActivity.getSystemService(mActivity.TELEPHONY_SERVICE);
                result.put("cellular", telephonyManager.getNetworkOperator());
            }
        } catch (JSONException e) {
            Log.d(TestEngine.TAG, "Error buidling JSON for network info", e);
        }
        // Log.d(TAG, "Network info: " + result.toString());
        return result;
        
    }
}