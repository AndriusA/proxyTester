package org.smarte.tcptester;

import android.net.LocalServerSocket;
import java.io.DataInputStream;
import android.net.LocalSocket;
import java.util.concurrent.locks.ReentrantLock;
import java.io.DataOutputStream;
import android.util.Log;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

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

    public boolean runTest(byte opcode, InetAddress src, int srcPort, InetAddress dst, int dstPort) {
        // Command consists of a number of bytes:
        // - 1 for length
        // - 1 for opcode
        // - 4 for source ip address
        // - 2 for source port number
        // - 4 for destination ip address
        // - 2 for destination port number
        byte commandLength = 1+1+4+2+4+2;
        ByteBuffer command = ByteBuffer.allocate(commandLength);
        // LTV (Length-Type-Value) encoded commands
        command.put(commandLength);
        command.put(opcode);
        command.put(src.getAddress());
        command.putShort((short) srcPort);
        command.put(dst.getAddress());
        command.putShort((short) dstPort);
        command.flip();
        // Send to the local (unix) socket
        this.send(command.array());    
        // Wait for response
        byte[] response = this.receiveCommand();
        // Magic opcode from IPC "protocol"
        if (response[1] == 0) { 
            Log.d(TAG, "Test successful");    
            return true;
        } else {
            return false;
        }
    }

    private boolean send(byte[] msg) {
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

    private byte[] receiveCommand() {
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