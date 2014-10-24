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

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import java.util.ArrayList;
import org.smarte.tcptester.R;

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