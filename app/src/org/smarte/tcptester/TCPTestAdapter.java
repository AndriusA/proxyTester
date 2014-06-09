package org.smarte.tcptester;

import android.widget.ArrayAdapter;
import android.view.View;
import android.content.Context;
import java.util.ArrayList;
import android.view.ViewGroup;
import android.view.LayoutInflater;
import android.widget.TextView;
import android.widget.ImageView;



public class TCPTestAdapter extends ArrayAdapter<TCPTest> {
    public TCPTestAdapter(Context context, ArrayList<TCPTest> results) {
        super(context, R.layout.item_test, results);
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        // Get the data item for this position
        TCPTest result = getItem(position);    
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
        testName.setText(result.name);
        testResult.setImageResource(result.result ? R.drawable.ic_action_accept : R.drawable.ic_action_warning);
        // Return the completed view to render on screen
        return convertView;
    }
}