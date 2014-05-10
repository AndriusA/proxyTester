package org.smarte.tcptester;

import android.app.Activity;
import android.widget.TextView;
import android.widget.Button;
import android.view.View;
import android.os.Bundle;
import android.content.Intent;
import android.content.Context;
import android.net.VpnService;
import android.net.NetworkInfo;
import android.net.ConnectivityManager;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.LocalServerSocket;
import android.util.Log;
import android.os.Build;
import android.os.AsyncTask;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;


public class SocketTesterServer extends Thread {
    public static final String TAG = "TCPTester";
    private static final String SOCKET_ADDRESS = "tcptester_socket";

    int bufferSize = 255;
    byte[] buffer;
    byte bytesRead;
    byte totalBytesRead;
    byte posOffset;
    LocalServerSocket server;
    LocalSocket receiver;
    private volatile boolean stopThread;
    private DataInputStream socketReader;
    private DataOutputStream socketWriter;
    private boolean clientConnected = false;

    final Lock lock = new ReentrantLock();
    final Condition connected  = lock.newCondition(); 

    public SocketTesterServer() {
        buffer = new byte[bufferSize];
        try {
            server = new LocalServerSocket(SOCKET_ADDRESS);
        } catch (IOException e) {
            Log.d(TAG, "Creating localSocketServer " + SOCKET_ADDRESS + " failed", e);
        }
    }

    public void run() { 
        

        try {
            Log.d(TAG, "localSocketServer accepts one client");
            receiver = server.accept();
            lock.lock();
            socketWriter = new DataOutputStream( receiver.getOutputStream() );
            socketReader = new DataInputStream( receiver.getInputStream() );
            clientConnected = true;
            Log.d(TAG, "Client connected, signaling condition");
            connected.signal();
        } catch (IOException e) {
            Log.d(TAG, "localSocketServer accept() failed", e);
            stopThread = true;
        } finally {
            lock.unlock();
        }

        while (!stopThread) {
            if (null == server){
                Log.d(TAG, "The localSocketServer is NULL");
                lock.lock();
                stopThread = true;
                lock.unlock();
                break;
            } else {
                try {
                    sleep(100);
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
        }

        finish();

        Log.d(TAG, "The LocalSocketServer thread stopping");
        
    }

    public void finish(){
        Log.d(TAG, "Finish SocketTesterServer comms thread");
        lock.lock();
        // Log.d(TAG, "Lock acquired");
        stopThread = true;            
        if (receiver != null){
            try {
                receiver.close();
            } catch (IOException e) {
                Log.e(TAG, "Error when closing LocalSocketServer receiver", e);
                e.printStackTrace();
            }
        }
        if (server != null){
            try {
                server.close();
            } catch (IOException e) {
                Log.e(TAG, "Error when closing LocalSocketServer server", e);
                e.printStackTrace();
            }
        }
        lock.unlock();
        Log.d(TAG, "Finished");
    }

    public boolean send(byte[] msg) {
        boolean result = false;
        lock.lock();
        try {
            Log.d(TAG, "Sending message " + RawSocketTester.bytesToHex(msg, msg[0]));
            if (!clientConnected) {
                Log.d(TAG, "Waiting for client to connect");
                connected.await();
            }
            
            Log.d(TAG, "Client connected, writing the message to socket");
            socketWriter.write(msg, 0, msg[0]);
            result = true;
        } catch (InterruptedException e) {
            Log.e(TAG, "connected condition waiting interrupted", e);
        } catch (IOException e) {
            Log.e(TAG, "error writing to socket", e);
        } finally {
            lock.unlock();
        }
        return result;
    }

    public byte[] receiveCommand() {
        lock.lock();
        bytesRead = 0;
        totalBytesRead = 0;
        posOffset = 0;
        while (receiver != null) {
            try {
                bytesRead = (byte)socketReader.read(buffer, posOffset, (bufferSize - totalBytesRead));
            } catch (IOException e) {
                Log.e(TAG, "Exception when reading socket", e);
                break;
            }

            if (bytesRead > 0) {
                posOffset += bytesRead;
                totalBytesRead += bytesRead;
                Log.d(TAG, "Receive data from socket, bytesRead = " + bytesRead + ", " + RawSocketTester.bytesToHex(buffer, totalBytesRead));
                byte cmdLen = buffer[0];
                if (cmdLen == totalBytesRead) {
                    Log.d(TAG, "Full command received");
                    break;
                }
            }
        }
        lock.unlock();
        return buffer;
    }
            

    public String getLocalSocketAddress() {
        return server.getLocalSocketAddress().getName();
    }

}