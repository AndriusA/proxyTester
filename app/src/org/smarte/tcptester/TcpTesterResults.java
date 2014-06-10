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

import java.util.ArrayList;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpPost;
import android.view.Menu;
import java.io.IOException;
import android.widget.ImageView;
import android.content.Context;
import android.widget.ListView;
import java.util.HashMap;
import org.apache.http.impl.client.DefaultHttpClient;
import android.widget.ArrayAdapter;
import android.os.AsyncTask;
import android.widget.TextView;
import android.net.NetworkInfo;
import java.util.List;
import android.view.View;
import org.apache.http.client.ResponseHandler;
import org.apache.http.message.BasicNameValuePair;
import java.io.UnsupportedEncodingException;
import android.view.ViewGroup;
import org.apache.http.impl.client.BasicResponseHandler;
import android.support.v7.app.ActionBarActivity;
import android.util.Log;
import android.net.ConnectivityManager;
import android.os.Bundle;
import android.view.LayoutInflater;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import java.util.Set;
import android.support.v7.app.ActionBar;

public class TcpTesterResults extends ActionBarActivity 
{
    public static final String TAG = "TCPTester";
    private TextView mStatus;
    protected TextView mSent;

    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.results);

        ActionBar actionBar = getSupportActionBar();
        actionBar.setDisplayHomeAsUpEnabled(true);
        actionBar.show();
        String status = this.getIntent().getStringExtra("status");
        ArrayList<TCPTest> results = getIntent().getParcelableArrayListExtra("results");

        mStatus = (TextView) findViewById(R.id.testFinished);
        if (status.equals("success"))
            mStatus.setText(getString(R.string.test_finished_success));
        else if (status.equals("prohibited"))
            mStatus.setText(getString(R.string.test_finished_prohibited));
        else
            mStatus.setText(getString(R.string.test_finished_failed));
        
        mSent = (TextView) findViewById(R.id.resultsPosted);

        populateDetailedResults(results);

        new PostResultsTask().execute(status, getPostResults(results));
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        return super.onCreateOptionsMenu(menu);
    }

    private void populateDetailedResults(ArrayList<TCPTest> results) {
        TextView globalIP = (TextView) findViewById(R.id.yourIP);
        // Aggregate results by port
        HashMap<Integer, Integer> successPerPort = new HashMap<Integer, Integer>();
        HashMap<Integer, Integer> totalPerPort = new HashMap<Integer, Integer>();
        for (TCPTest result : results) {
            // Don't count the test of getting global address as a test
            if (result.opcode == TCPTest.TEST_GET_GLOBAL_IP) {
                if (result.extras == null)
                    continue;
                String ip = "";
                for (int i = 0; i < 4; i++) {
                    ip += Integer.toString((int)(result.extras[i] & 0xFF)) + (i < 3 ? "." : "");
                }
                globalIP.setText(getString(R.string.your_IP) + " " + ip);
                continue;
            }
            if (result.result) {
                Integer count = successPerPort.get(result.dstPort);
                if (count == null)
                    count = 0;
                count++;
                successPerPort.put(result.dstPort, count);
            }
            Integer count = totalPerPort.get(result.dstPort);
            if (count == null)
                count = 0;
            count++;
            totalPerPort.put(result.dstPort, count);
        }
        Set<Integer> ports = totalPerPort.keySet();
        ArrayList<TCPTestAggregate> aggregateResults = new ArrayList<TCPTestAggregate>();
        for (Integer p : ports) {
            int success = (successPerPort.containsKey(p) ? successPerPort.get(p) : 0);
            aggregateResults.add(new TCPTestAggregate(p, success, totalPerPort.get(p)));
        }
        // Create the adapter to convert the array to views
        TCPTestAggregateAdapter adapter = new TCPTestAggregateAdapter(this, aggregateResults);
        // Attach the adapter to a ListView
        ListView listView = (ListView) findViewById(R.id.testDetailed);
        listView.setAdapter(adapter);
    }

    private String getPostResults(ArrayList<TCPTest> results) {
        String ret = "";
        ConnectivityManager connMgr = 
            (ConnectivityManager) getApplicationContext().getSystemService(CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connMgr.getActiveNetworkInfo();
        ret += "Network info: " + networkInfo.toString();
        for (TCPTest result : results) {
            ret += result.toString();
        }
        return ret;
    }

    public class TCPTestAggregate {
        public final Integer CLEAR = 0;
        public final Integer FILTERED = 1;
        public final Integer RESTRICTED = 2;

        private Integer dstPort;
        private Integer result;
        private String description;

        TCPTestAggregate(Integer dstPort, Integer passed, Integer total) {
            this.dstPort = dstPort;
            double successRate = ((double) passed) / total;
            if (successRate > 0.7) {
                this.result = CLEAR;
                this.description = "All traffic allowed";
            }
            else if (successRate > 0.01) {
                this.result = FILTERED;
                this.description = "Some extensions filtered";
            }
            else {
                this.result = RESTRICTED;
                this.description = "All extensions filtered";
            }
        }
    }

    public class TCPTestAggregateAdapter extends ArrayAdapter<TCPTestAggregate> {
        public TCPTestAggregateAdapter(Context context, ArrayList<TCPTestAggregate> results) {
            super(context, R.layout.item_test, results);
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            // Get the data item for this position
            TCPTestAggregate result = getItem(position);    
            // Check if an existing view is being reused, otherwise inflate the view
            if (convertView == null) {
                convertView = LayoutInflater.from(getContext()).inflate(R.layout.item_test, parent, false);
            }
            // Lookup view for data population
            TextView testPort = (TextView) convertView.findViewById(R.id.testPort);
            TextView testName = (TextView) convertView.findViewById(R.id.testName);
            ImageView testResult = (ImageView) convertView.findViewById(R.id.testResult);
            // Populate the data into the template view using the data object
            testPort.setText(Integer.toString(result.dstPort));
            testName.setText("\t"+result.description);
            if (result.result == result.CLEAR)
                testResult.setImageResource(R.drawable.ic_action_accept);
            if (result.result == result.FILTERED)
                testResult.setImageResource(R.drawable.ic_action_warning);
            if (result.result == result.RESTRICTED)
                testResult.setImageResource(R.drawable.ic_action_error);
            // Return the completed view to render on screen
            return convertView;
        }
    }

    
    private class PostResultsTask extends AsyncTask<String, Void, Boolean> {
        @Override protected Boolean doInBackground(String... results) {
            return postDataHttp(results[0], results[1]);
        }
    
        protected Boolean postDataHttp(String status, String results) {
            DefaultHttpClient httpclient = new DefaultHttpClient();
            HttpPost httpost = new HttpPost("http://tcptester.smart-e.org/result");
            List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(2);
            nameValuePairs.add(new BasicNameValuePair("id", "12345"));
            nameValuePairs.add(new BasicNameValuePair("status", status));
            // nameValuePairs.add(new BasicNameValuePair("duration", Long.toString()));
            nameValuePairs.add(new BasicNameValuePair("result", results));

            try {
                httpost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
                //Handles what is returned from the page 
                ResponseHandler responseHandler = new BasicResponseHandler();
                httpclient.execute(httpost, responseHandler);
                return true;
            } catch (UnsupportedEncodingException e) {
                Log.e(TAG, "Error Post'ing", e);
                return false;
            }  catch (IOException e) {
                Log.e(TAG, "Error Post'ing", e);
                return false;
            }
        }

        protected void onPostExecute(Boolean result) {
            if (result == true)
                mSent.setText(getString(R.string.results_posted));
            else
                mSent.setText(getString(R.string.results_post_failed));
        }

    }    
}
