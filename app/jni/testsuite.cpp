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

#include <android/log.h>
#include "testsuite.hpp"

// Setup RAW socket
// setsockopt calls for:
//      - allowing to manipulate full packet down to IP layer (IPPROTO_IP, IP_HDRINCL)
//      - timeout on recv'ing packets (SOL_SOCKET, SO_RCVTIMEO)
// param sock       socket as reference
test_error setupSocket(int &sock) {
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1) {
        LOGD("socket() failed");
        return test_failed;
    } else {
        LOGD("socket() ok");
    }

    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
        LOGE("setsockopt() failed: %s", strerror(errno));
        return test_failed;
    } else {
        LOGD("setsockopt() ok");
    }

    struct timeval tv;
    tv.tv_sec = sock_receive_timeout_sec.count();
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors
    if ( setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) == -1 ) {
        LOGE("setsockopt receive timeout failed: %s", strerror(errno));
    }

    return success;
}

// Generic function for running any test. Takes all parameters and runs the rest of the functions:
//      1. Sets up a new socket
//      2. Performs the parametrised three-way handshake
//      3. Sends a piece of data if the connection has been opened successfully
//      4. Expects a specific data response back (returns error code if the result doesn't match)
//      5. ACKs the received data
//      6. Cleanly shuts down the connection
//
// return   test_failed or test_complete codes depending on the outcome
test_error runTest(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port,
            uint32_t syn_ack, uint16_t syn_urg, uint8_t syn_res,
            uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res,
            char *synack_payload, int synack_length,
            uint8_t data_out_res, uint8_t data_in_res,
            char *send_payload, int send_length, char *expect_payload, int expect_length)
{
    int sock;
    char buffer[BUFLEN] = {0};
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct sockaddr_in src, dst;
    uint32_t seq_local, seq_remote;
    ip = (struct iphdr*) buffer;
    tcp = (struct tcphdr*) (buffer + IPHDRLEN);
    char *data = buffer + IPHDRLEN + TCPHDRLEN;

    if (setupSocket(sock) != success) {
        LOGE("Socket setup failed: %s", strerror(errno));
        return test_failed;
    }

    src.sin_family = AF_INET;
    src.sin_port = htons(src_port);
    src.sin_addr.s_addr = htonl(source);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = htonl(destination);

    test_error handshake_res = handshake(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, 
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res, synack_payload, synack_length);

    if (handshake_res != success)
    {
        LOGE("TCP handshake failed: %s", strerror(errno));
        return test_failed;
    }

    sendData(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, data_out_res, send_payload, send_length);
    int receiveLength = 0;
    test_error ret = success;
    if (receiveData(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, receiveLength) == success) {
        if (expect_length > receiveLength || memcmp(data, expect_payload, expect_length) != 0) {
            LOGD("Payload wrong value, received %d data bytes:", receiveLength);
            if (receiveLength > 0)
                printBufferHex(data, receiveLength);
            LOGD("Expected:");
            printBufferHex(expect_payload, expect_length);
            ret = test_failed;
        }
        if (tcp->res1 != (data_in_res & 0xF)) {
            LOGE("Data packet reserved field wrong value: %02X, expected %02X", tcp->res1, data_in_res & 0xF);
            ret = test_failed;
        }

        if (receiveLength > 0) {
            acknowledgeData(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, receiveLength);
        }
    }

    shutdownConnection(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote);

    if (ret != success)
        return test_failed;
    else
        return test_complete;
}

test_error runTest(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port,
            uint32_t syn_ack, uint16_t syn_urg, uint8_t syn_res,
            uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res,
            uint8_t data_out_res, uint8_t data_in_res,
            char *send_payload, int send_length, char *expect_payload, int expect_length)
{
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res, NULL, 0,
        data_out_res, data_in_res, send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_ack_only(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port) {
    uint32_t syn_ack = 0xbeef0001;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbeef0001";
    int send_length = strlen(send_payload);
    int expect_length = 4;
    char expect_payload[expect_length];
    expect_payload[0] = (syn_ack >> 8*3) & 0xFF;
    expect_payload[1] = (syn_ack >> 8*2) & 0xFF;
    expect_payload[2] = (syn_ack >> 8*1) & 0xFF;
    expect_payload[3] = syn_ack & 0xFF;
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_urg_only(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe02;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbe02";
    int send_length = strlen(send_payload);
    int expect_length = 2;
    char expect_payload[expect_length];
    expect_payload[0] = (syn_urg >> 8) & 0xFF;
    expect_payload[1] = syn_urg & 0xFF;
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_ack_urg(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0003;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0xbe03;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbe03";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_plain_urg(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0xbe04;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbe04";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_ack_data(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0xbeef000B;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    char synack_payload[] = "0B";
    int synack_length = 2;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbeef000B";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        synack_payload, synack_length,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_ack_checksum_incorrect(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0005;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbeef0005";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_ack_checksum_incorrect_seq(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0xbeef000D;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    // Different checksum to differentiate when which type of rewriting happens
    uint16_t synack_check = 0xbeee;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbeef000D";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_ack_checksum(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0006;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbeef0006";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_urg_urg(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe07;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0xbe07;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbe07";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_urg_checksum(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe08;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbe08";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_urg_checksum_incorrect(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe09;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO_0xbe09";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_reserved_syn(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port, uint8_t reserved)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;

    char send_payload[] = "HELLO_reserved_SYN";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    uint8_t result = 0;
    uint8_t syn_res = reserved;
    uint8_t synack_res = reserved;
    test_error res = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res == test_complete) {
        LOGD("Reserved byte %02X passed", reserved);
    }
    return res;
}

test_error runTest_reserved_est(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port, uint8_t reserved)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t syn_res = 0;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_reserved_EST";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);

    uint8_t result = 0;
    uint8_t data_out_res = reserved;
    uint8_t data_in_res = reserved;
    test_error res = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res == test_complete) {
        LOGD("Reserved byte %02X passed", reserved);
    }
    return res;
}

uint32_t getOwnIp(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;    
    char send_payload[] = "GETMYIP";
    int send_length = strlen(send_payload);

    int sock;
    char buffer[BUFLEN] = {0};
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct sockaddr_in src, dst;
    uint32_t seq_local, seq_remote;
    ip = (struct iphdr*) buffer;
    tcp = (struct tcphdr*) (buffer + IPHDRLEN);
    char *data = buffer + IPHDRLEN + TCPHDRLEN;

    if (setupSocket(sock) != success) {
        LOGE("Socket setup failed: %s", strerror(errno));
        return 0;
    }

    src.sin_family = AF_INET;
    src.sin_port = htons(src_port);
    src.sin_addr.s_addr = htonl(source);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = htonl(destination);

    if (handshake(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, 
        syn_ack, syn_urg, syn_res, 
        synack_urg, synack_check, synack_res) != success)
    {
        LOGE("TCP handshake failed: %s", strerror(errno));
        return 0;
    }

    sendData(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, data_out_res, send_payload, send_length);
    int receiveLength = 0;
    uint32_t global_source = 0;
    if (receiveData(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, receiveLength) == success) {
        // Needs to be 4 bytes address
        if (receiveLength == 4) {
            for (int b = 0; b < 4; b++) {
                global_source |= ( data[b] & (char)0xFF ) << (8 * (3-b));
            }
            LOGD("Received IP address response %d.%d.%d.%d", data[0], data[1], data[2], data[3]);
        } else {
            LOGE("IP address response wrong length %d", receiveLength);
        }

        if (receiveLength > 0) {
            acknowledgeData(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, receiveLength);
        }
    }
    shutdownConnection(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote);
    return global_source;
}
