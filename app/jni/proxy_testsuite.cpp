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
#include "proxy_testsuite.hpp"
#include <pthread.h>

using namespace std::placeholders;

struct handshake_thread_data{
    int thread_id;
    int sock;
    char *buffer;
    struct sockaddr_in src, dst;
    uint32_t seq_local, seq_remote;
    packetModifier fn_synExtras;
    packetFunctor fn_checkTcpSynAck;
};

void *threadedHandshake(void *threadarg) {
    struct handshake_thread_data *d;
    d = (struct handshake_thread_data *) threadarg;

    int sock = d->sock;
    char *buffer = d->buffer;
    struct iphdr *ip = (struct iphdr*) buffer;
    struct tcphdr *tcp = (struct tcphdr*) (buffer + IPHDRLEN);;
    struct sockaddr_in src = d->src;
    struct sockaddr_in dst = d->dst;
    uint32_t seq_local = d->seq_local;
    uint32_t seq_remote = d->seq_remote;
    packetModifier fn_synExtras = d->fn_synExtras;
    packetFunctor fn_checkTcpSynAck = d->fn_checkTcpSynAck;

    LOGD("Thread %d of the parallel handshake threads", d->thread_id);
    test_error result = handshake(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, fn_synExtras, fn_checkTcpSynAck);
    LOGD("Thread %d handshake result: %d", d->thread_id, result);
    pthread_exit((void*) result);
}

test_error runTest_doubleSyn(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port)
{
    // Packet fields
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;    
    char send_payload[] = "";
    int send_length = 0;
    char expect_payload[] = "";
    int expect_length = 0;
    char synack_payload[] = "";
    int synack_length = 0;

    packetModifier fn_synExtras = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2);
    packetFunctor fn_checkTcpSynAck = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2);

    // Socket data initialisation
    int sock;
    char buffer_1[BUFLEN] = {0};
    char buffer_2[BUFLEN] = {0};
    char buffer_3[BUFLEN] = {0};
    struct iphdr *ip_1, *ip_2;
    struct tcphdr *tcp_1, *tcp_2;
    struct sockaddr_in src, dst, src2;
    uint32_t seq_local_1, seq_remote_1, seq_local_2, seq_remote_2;
    ip_1 = (struct iphdr*) buffer_1;
    ip_2 = (struct iphdr*) buffer_2;
    tcp_1 = (struct tcphdr*) (buffer_1 + IPHDRLEN);
    tcp_2 = (struct tcphdr*) (buffer_2 + IPHDRLEN);
    char *data_1 = buffer_1 + IPHDRLEN + TCPHDRLEN;
    char *data_2 = buffer_2 + IPHDRLEN + TCPHDRLEN;

    src.sin_family = AF_INET;
    src.sin_port = htons(src_port);
    src.sin_addr.s_addr = htonl(source);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = htonl(destination);
    src2.sin_family = AF_INET;
    src2.sin_port = htons(src_port+1);
    src2.sin_addr.s_addr = htonl(source);

    // Socket setup
    if (setupSocket(sock) != success) {
        LOGE("Socket setup failed: %s", strerror(errno));
        return test_failed;
    } else {
        LOGD("Socket setup, initialising data");
    }

    // Setting up data structure to pass info to thread
    struct handshake_thread_data data_hs1, data_hs2, data_hs3;
    data_hs1.thread_id = 1;
    data_hs1.sock = sock;
    data_hs1.buffer = &buffer_1[0];
    data_hs1.src = src;
    data_hs1.dst = dst;
    data_hs1.seq_local = seq_local_1;
    data_hs1.seq_remote = seq_remote_1;
    data_hs1.fn_synExtras = fn_synExtras;
    data_hs1.fn_checkTcpSynAck = fn_checkTcpSynAck;

    data_hs2 = data_hs1;
    data_hs2.thread_id = 2;
    data_hs2.buffer = &buffer_2[0];
    data_hs2.src = src2;
    data_hs1.seq_local = seq_local_2;
    data_hs1.seq_remote = seq_remote_2;

    LOGD("Starting handshake threads");
    pthread_t thread_hs1, thread_hs2, thread_hs3;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    int rc_hs1 = pthread_create(&thread_hs1, &attr, threadedHandshake, (void *) &data_hs1);
    int rc_hs2 = pthread_create(&thread_hs2, &attr, threadedHandshake, (void *) &data_hs2);

    pthread_attr_destroy(&attr);
    void *status;
    LOGD("Waiting for both handshakes");
    rc_hs1 = pthread_join(thread_hs1, &status);
    rc_hs2 = pthread_join(thread_hs2, &status);

    test_error result = success;
    LOGD("Sleeping, then RSTing middle connection");
    sleep(10);
    LOGD("Build TCP RST");

    buildTcpAck(&src, &dst, ip_1, tcp_1, tcp_1->seq, tcp_1->ack_seq);
    tcp_1->window = 0;
    if (sendPacket(sock, buffer_1, &dst, ntohs(ip_1->tot_len)) != success) {
        LOGE("TCP handshake ACK failure: %s", strerror(errno));
        result = ack_error;
    }

    // char send_payload_rst[] = "CONNECTION_RESET_BY_PEER";
    // int send_length_rst = strlen(send_payload_rst);
    // buildTcpRst_data(&src2, &dst, ip_2, tcp_2, ntohl(tcp_2->seq), ntohl(tcp_2->ack_seq), 0, 0)
    // appendData(ip, tcp, send_payload_rst, send_length_rst);
    // LOGD("Send TCP RST");
    // if (sendPacket(sock, buffer_2, &dst, ntohs(ip_2->tot_len)) != success) {
    //     LOGE("TCP doubleSYN RST failure: %s", strerror(errno));
    //     result = rst_send_error;
    // }
    LOGD("Cycle done");
    sleep(5);
    LOGD("Testing finished, returning");
    return result;
}

test_error dummyCheck(struct iphdr *ip, struct tcphdr *tcp) {
    return success;
}

// Encode 
test_error runTest_sackGap(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port) {
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO_ACK_GAP";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    // SYN with all the fields set and SACK OK option
    packetModifier fn_synFields = std::bind(addSynExtras, syn_ack, syn_urg, syn_res, _1, _2);
    char *optionData = NULL;
    packetModifier fn_synOptions = std::bind(appendTcpOption, 0x04, 0x02, optionData, _1, _2);
    packetModifier fn_synExtras = std::bind(concatPacketModifiers, fn_synFields, fn_synOptions, _1, _2);
    // SYNACK checking
    packetFunctor fn_checkTcpSynAckValues = std::bind(checkTcpSynAck_np, synack_urg, synack_check, synack_res, _1, _2);
    bool sackEnabled = false;
    packetFunctor fn_checkSACK = std::bind(hasTcpOption, 0x04, std::ref(sackEnabled), _1, _2);
    packetFunctor fn_checkTcpSynAck = std::bind(concatPacketFunctors, fn_checkTcpSynAckValues, fn_checkSACK, _1, _2);
    // Send data with a gap after the handshake (trigger selective acknowledgment)
    packetModifier fn_appendData = std::bind(appendData, _1, _2, send_payload, send_length);
    packetModifier fn_changeSeq = std::bind(increaseSeq, 0xbe, _1, _2);
    packetModifier fn_makeRequest = std::bind(concatPacketModifiers, fn_appendData, fn_changeSeq, _1, _2);
    // Check if reply indicates recognised gap
    packetFunctor fn_checkResponseDummy = std::bind(dummyCheck, _1, _2);

    char send_payload2[0xbe] = {'b'};
    int send_length2 = 0xbe;
    packetModifier fn_appendData2 = std::bind(appendData, _1, _2, send_payload2, send_length2);
    packetFunctor fn_checkResponse2 = std::bind(checkData, expect_payload, expect_length, _1, _2);

    std::queue<std::pair<packetModifier, packetFunctor> > stepSequence;
    stepSequence.push(std::make_pair(fn_makeRequest, fn_checkResponseDummy));
    stepSequence.push(std::make_pair(fn_appendData2, fn_checkResponse2));
    
    return runTest(source, src_port, destination, dst_port,
        fn_synExtras, fn_checkTcpSynAck, stepSequence);
}
