#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>

#include <android/log.h>

#include "testsuite.hpp"

#ifndef TAG
#define TAG "TCPTester-bin"
#endif

#ifndef BUFLEN
#define BUFLEN 4096
#endif

#define SOCK_PATH "tcptester_socket"

enum opcode_t : uint8_t {
    HANDSHAKE_BEEF = 1,
    HANDSHAKE_CHECKSUM = 2,
    RESULT = 3
};

struct ipcmsg {
    u_int8_t length;
    opcode_t opcode;
};

int main() {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Starting TCPTester service");
    int s, t, len;
    struct sockaddr_un local;
    char buffer[BUFLEN];
    struct ipcmsg *ipc;
    ipc = (struct ipcmsg *) buffer;

    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Creating socket");
    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Fatal: Error opening unix socket %s", strerror(errno));
        exit(1);
    }

    local.sun_family = AF_UNIX;
    local.sun_path[0] = '\0';
    strcpy(local.sun_path+1, SOCK_PATH);
    // unlink(local.sun_path);
    len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(local.sun_path+1);
    int ret;

    __android_log_print(ANDROID_LOG_INFO, TAG, "Connecting from native to local socket");
    if (connect(s, (struct sockaddr *)&local, len) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Fatal: Error connecting to unix socket %s", strerror(errno));
        exit(1);
    }

    int offset = 0;
    bool open = true;
    while (open) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "Receiving from socket, offset %d", offset);
        int n = recv(s, buffer+offset, BUFLEN-offset, 0);
        __android_log_print(ANDROID_LOG_INFO, TAG, "Received %d bytes", n);
        if (n <= 0) {
            if (n < 0) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "Error while receiving from local unix socket %s", strerror(errno));
                open = false;
                break;
            } else {
                __android_log_print(ANDROID_LOG_DEBUG, TAG, "End of File");
                open = false;
                break;
            }
            
        }
        
        // IPC message read completely
        if (n >= ipc->length) {
            printBufferHex(buffer, ipc->length);
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Payload: %s\n", buffer+2);
            // TODO: parse and process the message

            if (ipc->opcode == HANDSHAKE_BEEF) {
                u_int32_t source = 0, destination = 0;
                u_int16_t src_port = 0, dst_port = 0;

                for (int b = 0; b < 4; b++) {
                    source |= ( (buffer[2 + b]) & (char)0xFF ) << (8 * b);
                    destination |= ( (buffer[2 + 4 + 2 + b]) & (char)0xFF ) << (8 * b);
                }
                for (int b = 0; b < 2; b++) {
                    src_port |= ( (buffer[2 + 4 + b]) & (char)0xFF ) << (8 * (1-b));
                    dst_port |= ( (buffer[2 + 4 + 2 + 4 + b]) & (char)0xFF ) << (8 * (1-b));
                }
                runTest(source, src_port, destination, dst_port);
            }
            memset(buffer, 0, BUFLEN);

            ipc->length = 1+1+strlen("response");
            ipc->opcode = RESULT;
            strcpy(buffer+2, "response");
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Sending message to the socket, opcode %d", RESULT);
            printBufferHex(buffer, ipc->length);
            int written = 0;
            while (true) {
                int ret = write(s, buffer+written, ipc->length - written);
                if (ret < 0) {
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "Error while sending to local unix socket %s", strerror(errno));
                    open = false;
                    break;
                } else if (ret < ipc->length) {
                    written += ret;
                    continue;
                } else {
                    break;
                }
            }
            offset = 0;
            memset(buffer, 0, BUFLEN);
        }
        else {
            offset = n;
        }
    }

    close(s);

}


// iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 6969 -j DROP