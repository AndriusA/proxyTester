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

import java.net.InetAddress;

public class TCPTest {
    public static final int TEST_GET_GLOBAL_IP = 21;


    public String name;
    public byte opcode;
    public boolean result = false;
    public byte[] extras;
    public InetAddress src;
    public int srcPort;
    public InetAddress dst;
    public int dstPort;
    public TCPTest(String name, int opcode) {
        this.name = name;
        this.opcode = (byte) opcode;
    }
    public TCPTest(String name, int opcode, int extras) {
        this(name, opcode);
        this.extras = new byte[1];
        this.extras[0] = (byte)extras;
    }
    public TCPTest(String name, int opcode, InetAddress dst, int dstPort, InetAddress src, int srcPort) {
        this(name, opcode);
        this.dst = dst;
        this.dstPort = dstPort;
        this.src = src;
        this.srcPort = srcPort;
    }
    public TCPTest(TCPTest t) {
        this.name = t.name;
        this.opcode = t.opcode;
        this.src = t.src;
        this.srcPort = t.srcPort;
        this.dst = t.dst;
        this.dstPort = t.dstPort;
        this.result = t.result;
        this.extras = t.extras;
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
    public TCPTest(TCPTest t, boolean result, int extras) {
        this(t);
        this.result = result;
        this.extras = new byte[1];
        this.extras[0] = (byte)extras;
    }
    public String toString() {
        String ret = " " + name 
            + " " + src.getHostAddress() + ":" + Integer.toString(srcPort) 
            + " to " + dst.getHostAddress() + ":" + Integer.toString(dstPort) 
            + (result == true ? " passed" : " failed");
        if (opcode == TEST_GET_GLOBAL_IP && extras != null && extras.length == 4) {
            ret += " ";
            for (int i = 0; i < 4; i++) {
                ret += Integer.toString((int)(extras[i] & 0xFF));
                if (i < 3)
                    ret += ".";
            }
        }
        else if (extras != null && extras.length > 0) {
            ret += " ";
            for (byte e : extras)
                ret += Integer.toBinaryString(e);
        }
        ret +=  "\n";
        return ret;
    }
}