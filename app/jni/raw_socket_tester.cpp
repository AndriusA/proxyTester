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
#include "proxy_testsuite.hpp"
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
    ACK_DATA = 15,
    GET_GLOBAL_IP = 21,
    RET_GLOBAL_IP = 22,
    PROXY_DOUBLE_SYN = 41,
    PROXY_SACK_GAP = 42,
    RESULT_NOT_IMPLEMENTED = 51,
};

// IPC message header, LTV-encoded (Length, Type, Value)
struct ipcmsg {
    u_int8_t length;
    opcode_t opcode;
};

int main() {
    LOGI("Starting TCPTester service v%d", 8);
    int s, t, len;
    struct sockaddr_un local;
    char buffer[BUFLEN];
    struct ipcmsg *ipc;
    ipc = (struct ipcmsg *) buffer;

    LOGD("Creating socket");
    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOGE("Fatal: Error opening unix socket %s", strerror(errno));
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
        LOGE("Fatal: Error connecting to unix socket %s", strerror(errno));
        exit(1);
    }

    int offset = 0;
    bool open = true;
    while (open) {
        LOGD("Receiving from socket, offset %d", offset);
        int n = recv(s, buffer+offset, BUFLEN-offset, 0);
        LOGD("Received %d bytes", n);
        if (n <= 0) {
            if (n < 0) {
                LOGE("Error while receiving from local unix socket %s", strerror(errno));
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
            opcode_t currentTest = ipc->opcode;
            if ( currentTest >= ACK_ONLY && currentTest <= RESULT_NOT_IMPLEMENTED ) {
                uint32_t source = 0, destination = 0;
                uint16_t src_port = 0, dst_port = 0;
                for (int b = 0; b < 4; b++) {
                    source |= ( (buffer[2 + b]) & (char)0xFF ) << (8 * (3-b));
                    destination |= ( (buffer[2 + 4 + 2 + b]) & (char)0xFF ) << (8 * (3-b));
                }
                for (int b = 0; b < 2; b++) {
                    src_port |= ( (buffer[2 + 4 + b]) & (char)0xFF ) << (8 * (1-b));
                    dst_port |= ( (buffer[2 + 4 + 2 + 4 + b]) & (char)0xFF ) << (8 * (1-b));
                }
                LOGD("Read src port %d", src_port);
                LOGD("Read dst port %d", dst_port);
                uint8_t reserved = 0;
                if ((currentTest == RESERVED_SYN || currentTest == RESERVED_EST) && n > 2+4+2+4+2) {
                    reserved = buffer[2+4+2+4+2];
                }
                LOGD("Selecting test for opcode %d", currentTest);
                switch (currentTest) {
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
                    case ACK_DATA:
                        result = runTest_ack_data(source, src_port, destination, dst_port);
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
                    // case PROXY_DOUBLE_SYN:
                    //     result = runTest_doubleSyn(source, src_port, destination, dst_port);
                    // case PROXY_SACK_GAP:
                    //     result = runTest_sackGap(source, src_port, destination, dst_port);
                    default:
                        result = test_not_implemented;
                        break;
                }
                
            }
            memset(buffer, 0, BUFLEN);

            ipc->length = 1+1;
            if (result == test_complete) {
                ipc->opcode = RESULT_SUCCESS;
            } else if (currentTest == GET_GLOBAL_IP) {
                LOGD("Responding with the global address");
                ipc->opcode = RET_GLOBAL_IP;
                ipc->length = 1 + 1 + 4;
            } else
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
// iptables -t filter -A OUTPUT -p tcp --tcp-flags RST RST -d 192.95.61.161 -j DROP  && iptables -t filter -A OUTPUT -p tcp --tcp-flags RST RST -d 192.95.61.161 -m ttl --ttl-gt 60  -j ACCEPT 
// ?? iptables -A INPUT -p tcp -s 192.95.61.161 -j DROP 

// tcpdump -nnXSs 0 'tcp and host 192.95.61.161'

// iptables -A INPUT -p tcp -s 192.95.61.161 -j DROP  && tcpdump -nnXSs 0 'tcp and host 192.95.61.161'
// iptables -t filter -A OUTPUT -p tcp --tcp-flags RST RST -d 192.95.61.161 -j DROP  && iptables -t filter -A OUTPUT -p tcp --tcp-flags RST RST -d 192.95.61.161 -m ttl --ttl-lt 60  -j ACCEPT && tcpdump -nnXSs 0 'tcp and host 192.95.61.161'
// iptables -t filter -A OUTPUT -p tcp --tcp-flags RST RST -d 192.95.61.161 -m ttl --ttl-gt 60 -j DROP  && tcpdump -nnXSs 0 'tcp and host 192.95.61.161'

// http://www.caida.org/workshops/isma/1102/slides/aims1102_sbauer.pdf
// following don't work:
// iptables -t mangle -A OUTPUT -p tcp -d 192.95.61.161 -m tos --tos 0x00 -j TOS --set-tos 0x01
// iptables -t mangle -A OUTPUT -p tcp -d 192.95.61.161 -m ttl -j TTL --ttl-dec 1
// (modules not present...) cat /proc/net/ip_tables_targets