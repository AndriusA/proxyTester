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
    RESULT_SUCCESS = 0,
    RESULT_FAIL = 1,
    ACK_ONLY = 2,
    URG_ONLY = 3,
    ACK_URG = 4,
    PLAIN_URG = 5,
    ACK_CHECKSUM_INCORRECT = 6,
    ACK_CHECKSUM = 7,
    URG_URG = 8,
    URG_CHECKSUM = 9,
    URG_CHECKSUM_INCORRECT = 10,
    RESERVED_SYN = 11,
    RESERVED_EST = 12,
    RESULT_NOT_IMPLEMENTED = 61
};

struct ipcmsg {
    u_int8_t length;
    opcode_t opcode;
};

int main() {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Starting TCPTester service v%d", 2);
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
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Payload: ");
            printBufferHex(buffer, ipc->length);
            // TODO: parse and process the message

            test_error result = test_failed;    // by default
            if ( ipc->opcode >= ACK_ONLY && ipc->opcode <= RESERVED_EST ) {
                u_int32_t source = 0, destination = 0;
                u_int16_t src_port = 0, dst_port = 0;
                for (int b = 0; b < 4; b++) {
                    source |= ( (buffer[2 + b]) & (char)0xFF ) << (8 * (3-b));
                    destination |= ( (buffer[2 + 4 + 2 + b]) & (char)0xFF ) << (8 * (3-b));
                }
                for (int b = 0; b < 2; b++) {
                    src_port |= ( (buffer[2 + 4 + b]) & (char)0xFF ) << (8 * (1-b));
                    dst_port |= ( (buffer[2 + 4 + 2 + 4 + b]) & (char)0xFF ) << (8 * (1-b));
                }
                switch (ipc->opcode) {
                    case ACK_ONLY:
                        result = runTest_ack_only(source, src_port, destination, dst_port);
                        break;
                    case URG_ONLY:
                        result = runTest_urg_only(source, src_port, destination, dst_port);
                        break;
                    case ACK_URG:
                        result = runTest_ack_urg(source, src_port, destination, dst_port);
                        break;
                    case PLAIN_URG:
                        result = runTest_plain_urg(source, src_port, destination, dst_port);
                        break;
                    case ACK_CHECKSUM_INCORRECT:
                        result = runTest_ack_checksum_incorrect(source, src_port, destination, dst_port);
                        break;
                    case ACK_CHECKSUM:
                        result = runTest_ack_checksum(source, src_port, destination, dst_port);
                        break;
                    case URG_URG:
                        result = runTest_urg_urg(source, src_port, destination, dst_port);
                        break;
                    case URG_CHECKSUM:
                        result = runTest_urg_checksum(source, src_port, destination, dst_port);
                        break;
                    case URG_CHECKSUM_INCORRECT:
                        result = runTest_urg_checksum_incorrect(source, src_port, destination, dst_port);
                        break;
                    case RESERVED_SYN:   
                        result = runTest_reserved_syn(source, src_port, destination, dst_port);
                        break;
                    case RESERVED_EST:
                        result = runTest_reserved_est(source, src_port, destination, dst_port);
                        break;
                    default:
                        result = test_not_implemented;
                        break;
                }
                
            }
            memset(buffer, 0, BUFLEN);

            ipc->length = 1+1;
            if (result == test_complete)
                ipc->opcode = RESULT_SUCCESS;
            else
                ipc->opcode = RESULT_FAIL;
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Sending message to the socket, opcode %d", ipc->opcode);
            int ret = write(s, buffer, ipc->length);
            memset(buffer, 0, BUFLEN);
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Test complete");
        }
        else {
            offset = n;
        }
    }

    close(s);

}


// iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 6969 -j DROP