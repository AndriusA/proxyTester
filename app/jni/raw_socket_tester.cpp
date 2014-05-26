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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>

#include <android/log.h>

#include "testsuite.hpp"
#include "util.hpp"

#ifndef TAG
#define TAG "TCPTester-bin"
#endif

#ifndef BUFLEN
#define BUFLEN 4096
#endif

#define SOCK_PATH "tcptester_socket"

// IPC messaging opcodes for the different tests to be run;
// Testing is orchestrated by the Java code, over local Unix sockets
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
    ACK_CHECKSUM_INCORRECT_SEQ = 13,
    ACK_CHECKSUM_SEQ = 14,
    RESULT_NOT_IMPLEMENTED = 51,
};

// IPC message header, LTV-encoded (Length, Type, Value)
struct ipcmsg {
    u_int8_t length;
    opcode_t opcode;
};

int main() {
    LOGI("Starting TCPTester service v%d", 6);
    int s, t, len;
    struct sockaddr_un local;
    char buffer[BUFLEN];
    struct ipcmsg *ipc;
    ipc = (struct ipcmsg *) buffer;

    LOGD("Creating socket");
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

    LOGI("Connecting from native to local socket");
    if (connect(s, (struct sockaddr *)&local, len) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Fatal: Error connecting to unix socket %s", strerror(errno));
        exit(1);
    }

    int offset = 0;
    bool open = true;
    while (open) {
        LOGI("Receiving from socket, offset %d", offset);
        int n = recv(s, buffer+offset, BUFLEN-offset, 0);
        LOGI("Received %d bytes", n);
        if (n <= 0) {
            if (n < 0) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "Error while receiving from local unix socket %s", strerror(errno));
                open = false;
                break;
            } else {
                LOGD("End of File");
                open = false;
                break;
            }
            
        }
        
        // IPC message read completely
        if (n >= ipc->length) {
            LOGD("Payload: ");
            printBufferHex(buffer, ipc->length);
            // TODO: parse and process the message

            test_error result = test_failed;    // by default
            int result_code = 0;
            if ( ipc->opcode >= ACK_ONLY && ipc->opcode <= ACK_CHECKSUM_SEQ ) {
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
                uint8_t reserved = 0;
                if (n > 2+4+2+4+2)
                    reserved = buffer[2+4+2+4+2];
                LOGD("Selecting test for opcode %d", ipc->opcode);
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
                        result = runTest_reserved_syn(source, src_port, destination, dst_port, reserved);
                        break;
                    case RESERVED_EST:
                        result = runTest_reserved_est(source, src_port, destination, dst_port, reserved);
                        break;
                    case ACK_CHECKSUM_INCORRECT_SEQ:
                        result = runTest_ack_checksum_incorrect_seq(source, src_port, destination, dst_port);
                        break;
                    default:
                        result = test_not_implemented;
                        break;
                }
                
            }
            memset(buffer, 0, BUFLEN);

            ipc->length = 1+1;
            if (result == test_complete) {
                ipc->opcode = RESULT_SUCCESS;
            }
            else
                ipc->opcode = RESULT_FAIL;
            LOGD("Sending message to the socket, opcode %d", ipc->opcode);
            int ret = write(s, buffer, ipc->length);
            memset(buffer, 0, BUFLEN);
            LOGD("Test complete");
        }
        else {
            offset = n;
        }
    }

    close(s);

}

// iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 6969 -j DROP 