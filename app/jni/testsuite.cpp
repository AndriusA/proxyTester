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
#include <functional>
#include "testsuite.hpp"

using namespace std::placeholders;

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
        LOGD("setsockopt IP_HDRINCL ok");
    }

    struct timeval tv;
    tv.tv_sec = sock_receive_timeout_sec.count();
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors
    if ( setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) == -1 ) {
        LOGE("setsockopt receive timeout failed: %s", strerror(errno));
    } else {
        LOGD("setsockopt timeout ok");
    }

    return success;
}

// Function very specific to our tests and relies on packet checksum
// being computed in a specific way:
//      - The sending side decides the target checksum value
//      - Subtracts the destination IP address and port from that value
//      - If there is an intermediate NAT, it hopefully only modifies
//        the destination port and/or address and recomputes checksum
//        according to RFC3022
//      - It is sufficient to add back the (potentially new) destination address
//        to the received checksum to obtain the sender's target one
uint16_t undo_natting(struct iphdr *ip, struct tcphdr *tcp) {
    uint32_t checksum = ntohs(tcp->check);
    // Add back destination (own!) IP address and port number to undo what NAT modifies
    checksum = csum_add(checksum, ntohs(ip->daddr & 0xFFFF));
    checksum = csum_add(checksum, ntohs((ip->daddr >> 16) & 0xFFFF));
    checksum = csum_add(checksum, ntohs(tcp->dest));
    LOGD("Checksum NATing recalculated: %d, %04X", checksum, checksum);
    return (uint16_t) checksum;
}

uint16_t undo_natting_seq(struct iphdr *ip, struct tcphdr *tcp) {
    uint32_t checksum = ntohs(tcp->check);
    // Undo the simple NATing
    checksum = undo_natting(ip, tcp);
    checksum = csum_add(checksum, ntohs(tcp->seq & 0xFFFF));
    checksum = csum_add(checksum, ntohs((tcp->seq >> 16) & 0xFFFF));
    checksum = csum_add(checksum, ntohs(tcp->ack_seq & 0xFFFF));
    checksum = csum_add(checksum, ntohs((tcp->ack_seq >> 16) & 0xFFFF));
    LOGD("Checksum NATing recalculated (Seq): %d, %04X", checksum, checksum);
    return (uint16_t) checksum;
}

// Function that checks whether received SYNACK packet matches all the requirements:
// - urgent pointer
// - checksum (subject to undone natting)
// - reserved flags
// - expected payload
test_error checkTcpSynAck(uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res, 
            char *synack_payload, uint16_t synack_length, 
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state) 
{
    if (synack_urg != 0 && ntohs(tcp->urg_ptr) != synack_urg) {
        LOGE("SYNACK packet expected urg %04X, got: %04X", synack_urg, ntohs(tcp->urg_ptr));
        return synack_error_urg;
    }
    if (synack_check != 0) {
        uint16_t check = undo_natting(ip, tcp);
        uint16_t check2 = undo_natting_seq(ip, tcp);
        if (synack_check != check && synack_check != check2) {
            LOGE("SYNACK packet expected check %04X, got: %04X or %04X", synack_check, check, check2);
            return synack_error_check;
        }
    }
    if (synack_res != 0 && synack_res != (tcp->res1 & 0xF) ) {
        LOGE("SYNACK packet expected res %02X, got: %02X", synack_res, (tcp->res1 & 0xF));
        return synack_error_res;
    }

    char *data = (char*) ip + IPHDRLEN + tcp->doff * 4;
    uint16_t datalen = 0;
    uint16_t data_read = ntohs(ip->tot_len) - IPHDRLEN - tcp->doff * 4;
    if (synack_length > 0) {
        if (data_read != synack_length) {
            LOGD("SYNACK data_read different than expected");
            return synack_error_data_length;
        }
        else if (memcmp(data, synack_payload, synack_length) != 0) {
            LOGD("SYNACK data different than expected");
            return synack_error_data;
        }
        LOGD("SYNACK data received as expected");
    }
    return success;
}

test_error checkTcpSynAck_np(uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res,  
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state) {
    return checkTcpSynAck(synack_urg, synack_check, synack_res, NULL, 0, ip, tcp, conn_state);
}

test_error checkData(char *expect_payload, uint16_t expect_length, 
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state) 
{
    int receiveLength = ntohs(ip->tot_len) - IPHDRLEN - tcp->doff*4;
    char *data = (char *) ip + IPHDRLEN + tcp->doff*4;
    if (expect_length != receiveLength) {
        return receive_error_data_length;
    } else if (memcmp(data, expect_payload, expect_length) != 0) {
        LOGD("Payload wrong value, received %d data bytes:", receiveLength);
        if (receiveLength > 0)
            printBufferHex(data, receiveLength);
        LOGD("Expected:");
        printBufferHex(expect_payload, expect_length);
        return receive_error_data_value;
    } else {
        return success;
    }
}

test_error checkRes(uint8_t res, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state) {
    if (tcp->res1 != (res & 0xF)) {
        LOGE("Data packet reserved field wrong value: %02X, expected %02X", tcp->res1, res & 0xF);
        return receive_error_res_value;
    } else {
        return success;
    }
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
            packetModifier fn_synExtras, packetChecker fn_checkTcpSynAck, 
            packetModifier fn_makeRequest, packetChecker fn_checkResponse)
{
    std::queue<std::pair<packetModifier, packetChecker> > stepSequence;
    stepSequence.push(std::make_pair(fn_makeRequest, fn_checkResponse));
    return runTest(source, src_port, destination, dst_port, fn_synExtras, fn_checkTcpSynAck, stepSequence);
}
test_error runTest(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port,
            packetModifier fn_synExtras, packetChecker fn_checkTcpSynAck, 
            std::queue<std::pair<packetModifier, packetChecker> > stepSequence)
{
    int sock;
    char buffer[BUFLEN] = {0};
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct tcp_opt state;
    struct tcp_opt *conn_state = &state;
    struct sockaddr_in src, dst;
    ip = (struct iphdr*) buffer;
    tcp = (struct tcphdr*) (buffer + IPHDRLEN);

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

    test_error handshake_ret = handshake(sock, ip, tcp, conn_state, &src, &dst, fn_synExtras, fn_checkTcpSynAck);

    if (handshake_ret != success) {
        LOGE("TCP handshake failed: %s", strerror(errno));
        return handshake_ret;
    } else {
        LOGD("TCP handshake successful");
    }

    char dataBuffer[BUFLEN] = {0};
    uint32_t remote_isn = conn_state->rcv_nxt;
    conn_state->sack_ok = 0;
    int step = 0;
    while (!stepSequence.empty()) {
        std::pair<packetModifier, packetChecker> operations = stepSequence.front();
        packetModifier f_makeRequest = operations.first;
        packetChecker f_checkResponse = operations.second;
    
        LOGD("STEP %d: Send request", step);
        buildTcpAck(&src, &dst, ip, tcp, conn_state->snd_nxt, conn_state->rcv_nxt);
        uint32_t ts_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>
            (std::chrono::system_clock::now().time_since_epoch()).count();
        conn_state->rcv_tsval = ts_timestamp;
        appendTimestamp(ip, tcp, conn_state);
        f_makeRequest(ip, tcp, conn_state);
        sendPacket(sock, buffer, &dst, ntohs(ip->tot_len));

        test_error ret = success;
        uint16_t receiveLength;
        uint16_t receiveDataLength = 0;
        uint16_t newDataLength = 0;
        bool anythingReceived = false;
        // Receive packets until there is a packet with data or we timeout
        LOGD("STEP %d: Receive response", step);
        while ( !(receiveDataLength > 0) ) {
            test_error ret_receive = receivePacket(sock, ip, tcp, &dst, &src);
            receiveLength = ntohs(ip->tot_len);
            if (ret_receive != success){
                if (!anythingReceived) {
                    // Absolutely nothing has been received as a response to this packet
                    // assume failure
                    LOGD("STEP %d: Failure receiving any response", step);
                    return ret_receive;
                } else {
                    LOGD("STEP %d: Received an empty response", step);
                    // A packet (presumably an ACK has been received previously, but no data - fail softly)
                    break;
                }
            } 
            receiveDataLength = receiveLength - IPHDRLEN - tcp->doff * 4;
            anythingReceived = true;
            LOGD("STEP %d: check for timestamp option", step);
            hasTcpOption(TCPOPT_TIMESTAMP, ip, tcp, conn_state);
            // Advance own acknowledged data
            if (ntohl(tcp->ack_seq) > conn_state->snd_nxt)
                conn_state->snd_nxt = ntohl(tcp->ack_seq);
        }
        
        // Continuous block received and adds new data
        if (ntohl(tcp->seq) <= conn_state->rcv_nxt && conn_state->rcv_nxt < ntohl(tcp->seq) + receiveDataLength + 1)
            conn_state->rcv_nxt = ntohl(tcp->seq) + receiveDataLength;

        LOGD("STEP %d: Check response", step);
        // apply any custom checks to the response
        ret = f_checkResponse(ip, tcp, conn_state);
        sackResponseHandler(ip, tcp, conn_state);
        // If response is expected or at least acceptable
        if (ret == success || ret == response_acceptable) {
            LOGD("STEP %d: Saving %d bytes of data", step, receiveDataLength);
            char *payload = (char*) (buffer + IPHDRLEN + tcp->doff * 4);
            memcpy(payload, dataBuffer + ntohl(tcp->seq) - remote_isn, receiveDataLength);
        } else {
            // Test failed - response not acceptable
            LOGD("STEP %d: Test failed, response not acceptable", step);
            return ret;
        }

        // And if there was any data, ACK
        if (receiveDataLength > 0) {
            LOGD("STEP %d: Acknowledging data", step);
            buildTcpAck(&src, &dst, ip, tcp, conn_state->snd_nxt, conn_state->rcv_nxt);
            appendSackBlock(ip, tcp, conn_state);
            appendTimestamp(ip, tcp, conn_state);
            sendPacket(sock, buffer, &dst, ntohs(ip->tot_len));
        }
        stepSequence.pop();
        step++;
    }

    shutdownConnection(&src, &dst, sock, ip, tcp, conn_state->snd_nxt, conn_state->rcv_nxt);

    return success;
}

test_error runTest_ack_only(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0001;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_0xbeef0001";
    int send_length = strlen(send_payload);
    uint16_t expect_length = 4;
    char expect_payload[] = { (char) ((syn_ack >> 8*3) & 0xFF), (char) ((syn_ack >> 8*2) & 0xFF),
        (char) ((syn_ack >> 8*1) & 0xFF), (char) (syn_ack & 0xFF)};

    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}

test_error runTest_urg_only(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe02;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_0xbe02";
    int send_length = strlen(send_payload);
    uint16_t expect_length = 2;
    char expect_payload[] = {(char) ((syn_urg >> 8) & 0xFF), (char) (syn_urg & 0xFF)};

    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}

test_error runTest_ack_urg(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0003;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0xbe03;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_0xbe03";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    uint16_t expect_length = strlen(expect_payload);
    
    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}

test_error runTest_plain_urg(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0xbe04;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_0xbe04";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
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
    
    char send_payload[] = "HELLO_0xbeef000B";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck, synack_urg, synack_check, synack_res, synack_payload, synack_length, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}

test_error runTest_ack_checksum_incorrect(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0005;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_0xbeef0005";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
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
    
    char send_payload[] = "HELLO_0xbeef000D";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}

test_error runTest_ack_checksum(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0006;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_0xbeef0006";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}

test_error runTest_urg_urg(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe07;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0xbe07;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_0xbe07";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}

test_error runTest_urg_checksum(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe08;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_0xbe08";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}

test_error runTest_urg_checksum_incorrect(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe09;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_0xbe09";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}

test_error runTest_reserved_syn(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port, uint8_t reserved)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;

    char send_payload[] = "HELLO_reserved_SYN";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);

    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, reserved, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, reserved, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
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

    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2, _3);
    packetChecker fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2, _3);

    packetModifier fn_setRes = std::bind(setRes, reserved, _1, _2, _3);
    packetModifier fn_appendData = std::bind(appendData, send_payload, send_length, _1, _2);
    packetModifier fn_makeRequest = std::bind(concatPacketModifiers, fn_setRes, fn_appendData, _1, _2, _3);

    packetChecker fn_checkData = std::bind(checkData, expect_payload, expect_length, _1, _2, _3);
    packetChecker fn_checkRes = std::bind(checkRes, reserved, _1, _2, _3);
    packetChecker fn_checkResponse = std::bind(concatPacketCheckers, fn_checkData, fn_checkRes, _1, _2, _3);
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, fn_appendData, fn_checkData);
}