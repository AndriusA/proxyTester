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

import java.net.InetAddress;
import java.net.UnknownHostException;
import android.os.Parcelable;
import android.os.Parcel;
import android.util.Log;
import org.json.JSONObject;
import org.json.JSONException;

public class TCPTest implements Parcelable {
    //RawSocketTester tests
    public static final int ACK_ONLY = 2;
    public static final int URG_ONLY = 3;
    public static final int ACK_URG = 4;
    public static final int PLAIN_URG = 5;
    public static final int ACK_CHECKSUM_INCORRECT = 6;
    public static final int ACK_CHECKSUM = 7;
    public static final int ACK_DATA = 15;
    public static final int URG_URG = 8;
    public static final int URG_CHECKSUM = 9;
    public static final int URG_CHECKSUM_INCORRECT = 10;
    public static final int RESERVED_SYN = 11;
    public static final int RESERVED_EST = 12;
    public static final int ACK_CHECKSUM_INCORRECT_SEQ = 13;

    //RawSocketTester Proxy tests

    public static final int PROXY_DOUBLE_SYN = 41;
    public static final int PROXY_SACK_GAP = 42;

    //Netalyzr tests
    public static final int CHECK_LOCAL_ADDRESS = 31;
    public static final int CHECK_UDP = 32;
    public static final int DNS_IPV6_SUPPORT = 33;
    public static final int IPV6 = 34;
    public static final int MTU = 35;
    public static final int IPV6_MTU = 36;
    public static final int HIDDEN_PROXY = 37;


    public String name;
    public byte opcode;
    public boolean result;
    public String resultExtras;
    public InetAddress src;
    public int srcPort;
    public InetAddress dst;
    public int dstPort;
    public byte inputExtras;

    public TCPTest(String name, int opcode) {
        this.name = name;
        this.opcode = (byte) opcode;
        // unsuccessful by default
        this.result = false;
        this.srcPort = 0;
        this.dstPort = 0;
        this.inputExtras = 0;
    }
    public TCPTest(String name, int opcode, String resultExtras) {
        this(name, opcode);
        this.resultExtras = resultExtras;
    }
    public TCPTest(String name, int opcode, int inputExtras) {
        this(name, opcode);
        this.inputExtras = (byte)inputExtras;
    }
    public TCPTest(String name, int opcode, InetAddress dst, int dstPort, InetAddress src, int srcPort) {
        this(name, opcode);
        this.dst = dst;
        this.dstPort = dstPort;
        this.src = src;
        this.srcPort = srcPort;
    }
    public TCPTest(String name, int opcode, InetAddress dst, int dstPort, InetAddress src, int srcPort, boolean result) {
        this(name, opcode, dst, dstPort, src, srcPort);
        this.result = result;
    }
    public TCPTest(String name, int opcode, InetAddress dst, int dstPort, InetAddress src, int srcPort, boolean result, String resultExtras) {
        this(name, opcode, dst, dstPort, src, srcPort, result);
        this.resultExtras = resultExtras;
    }

    public TCPTest(TCPTest t) {
        this.name = t.name;
        this.opcode = t.opcode;
        this.src = t.src;
        this.srcPort = t.srcPort;
        this.dst = t.dst;
        this.dstPort = t.dstPort;
        this.result = t.result;
        this.resultExtras = t.resultExtras;
    }
    public TCPTest(TCPTest t, InetAddress dst, int dstPort, InetAddress src, int srcPort) {
        this(t);
        this.dst = dst;
        this.dstPort = dstPort;
        this.src = src;
        this.srcPort = srcPort;
    }
    public TCPTest(TCPTest t, boolean result) {
        this(t);
        this.result = result;
    }
    public TCPTest(TCPTest t, boolean result, String resultExtras) {
        this(t);
        this.result = result;
        this.resultExtras = resultExtras;
    }

    public int describeContents() {
        return 0;
    }

    private TCPTest(Parcel in) {
        name = in.readString();
        opcode = in.readByte();
        result = in.readByte() == 1 ? true : false;
        resultExtras = in.readString();
        byte[] tempSrc = new byte[4];
        in.readByteArray(tempSrc);
        try {
            src = InetAddress.getByAddress(tempSrc);
        } catch (UnknownHostException e) {
            src = null;
        }
        srcPort = in.readInt();

        byte[] tempDst = new byte[4];
        in.readByteArray(tempDst);
        try {
            dst = InetAddress.getByAddress(tempDst);
        } catch (UnknownHostException e) {
            dst = null;
        }
        dstPort = in.readInt();
    }

    public void writeToParcel(Parcel out, int flags) {
        out.writeString(name);
        out.writeByte(opcode);
        out.writeByte((byte) (result ? 1 : 0));
        out.writeString(resultExtras);
        out.writeByteArray(src.getAddress());
        out.writeInt(srcPort);
        out.writeByteArray(dst.getAddress());
        out.writeInt(dstPort);
    }

    public static final Parcelable.Creator<TCPTest> CREATOR
            = new Parcelable.Creator<TCPTest>() {
        public TCPTest createFromParcel(Parcel in) {
            return new TCPTest(in);
        }

        public TCPTest[] newArray(int size) {
            return new TCPTest[size];
        }
     };

    public String toString() {
        String ret = " " + name 
            + " " + src.getHostAddress() + ":" + Integer.toString(srcPort) 
            + " to " + dst.getHostAddress() + ":" + Integer.toString(dstPort) 
            + (result == true ? " passed" : " failed");
        if (resultExtras != null && resultExtras.length() > 0) {
            ret += " ";
            ret += resultExtras;
        }
        ret +=  "\n";
        return ret;
    }

    public JSONObject toJSON() {
        JSONObject jsonObj = new JSONObject();
        try {
            // Here we convert Java Object to JSON 
            jsonObj.put("name", name); // Set the first name/pair 
            jsonObj.put("opcode", opcode);
            jsonObj.put("result", result);
            if (src != null)
                jsonObj.put("srcAddress", src.getHostAddress());
            jsonObj.put("srcPort", srcPort);
            if (dst != null)
                jsonObj.put("dstAddress", dst.getHostAddress());
            jsonObj.put("dstPort", dstPort);
            jsonObj.put("extras", resultExtras);
        }
        catch(JSONException e) {
            Log.d(TestEngine.TAG, "Error buidling JSON from TCPTest", e);
        }
        return jsonObj;
    }
}