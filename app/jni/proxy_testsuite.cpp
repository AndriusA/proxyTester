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

struct handshake_thread_data{
    int thread_id;
    int sock;
    char *buffer;
    struct sockaddr_in src, dst;
    uint32_t seq_local, seq_remote;
    uint32_t syn_ack;
    uint16_t syn_urg, synack_urg;
    uint8_t syn_res, synack_res;
    uint16_t synack_check;
};

void *threadedHandshake(void *threadarg) {
    struct handshake_thread_data *d;
    d = (struct handshake_thread_data *) threadarg;

    uint32_t syn_ack = d->syn_ack;
    uint16_t syn_urg = d->syn_urg;
    uint8_t syn_res = d->syn_res;
    uint16_t synack_urg = d->synack_urg;
    uint16_t synack_check = d->synack_check;
    uint8_t synack_res = d->synack_res;
    int sock = d->sock;
    char *buffer = d->buffer;
    struct iphdr *ip = (struct iphdr*) buffer;
    struct tcphdr *tcp = (struct tcphdr*) (buffer + IPHDRLEN);;
    struct sockaddr_in src = d->src;
    struct sockaddr_in dst = d->dst;
    uint32_t seq_local = d->seq_local;
    uint32_t seq_remote = d->seq_remote;

    LOGD("Thread %d of the parallel handshake threads", d->thread_id);
    int result = handshake(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, 
        syn_ack, syn_urg, syn_res, 
        synack_urg, synack_check, synack_res);
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

    // Socket data initialisation
    int sock;
    char buffer_1[BUFLEN] = {0};
    char buffer_2[BUFLEN] = {0};
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
    src2.sin_port = htons(src_port+2);
    src2.sin_addr.s_addr = htonl(source);

    // Socket setup
    if (setupSocket(sock) != success) {
        LOGE("Socket setup failed: %s", strerror(errno));
        return test_failed;
    } else {
        LOGD("Socket setup, initialising data");
    }

    // Setting up data structure to pass info to thread
    struct handshake_thread_data data_hs1, data_hs2;
    data_hs1.thread_id = 1;
    data_hs1.sock = sock;
    data_hs1.buffer = &buffer_1[0];
    data_hs1.src = src;
    data_hs1.dst = dst;
    data_hs1.seq_local = seq_local_1;
    data_hs1.seq_remote = seq_remote_1;
    data_hs1.syn_ack = syn_ack;
    data_hs1.syn_urg = syn_urg;
    data_hs1.synack_urg = synack_urg;
    data_hs1.syn_res = syn_res;
    data_hs1.synack_res = synack_res;
    data_hs1.synack_check = synack_check;
    data_hs2 = data_hs1;
    data_hs2.thread_id = 2;
    data_hs2.buffer = &buffer_2[0];
    data_hs2.src = src2;

    LOGD("Starting handshake threads");
    pthread_t thread_hs1, thread_hs2;
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
    LOGD("Sleeping, then RSTing");
    sleep(10);
    LOGD("Build TCP RST");
    buildTcpRst(&src2, &dst, ip_2, tcp_2, ntohl(tcp_2->seq), ntohl(tcp_2->ack_seq), 0, 0);
    LOGD("Send TCP RST");
    if (!sendPacket(sock, buffer_2, &dst, ntohs(ip_2->tot_len))) {
        LOGE("TCP doubleSYN RST failure: %s", strerror(errno));
        result = send_error;
    }
    LOGD("Cycle done");
    sleep(5);
    LOGD("Testing finished, returning");
    return result;
}

// void manualHandshake() {
//     buildTcpSyn(&src, &dst, ip, tcp, syn_ack, syn_urg, syn_res);
//     if (!sendPacket(sock, buffer, &dst, ntohs(ip->tot_len))) {
//         LOGE("TCP doubleSYN 2 first SYN packet failure: %s", strerror(errno));
//         return send_error;
//     }
//     uint32_t seq_local_1 = ntohl(tcp->seq) + 1;
//     buildTcpSyn(&src2, &dst, ip, tcp, syn_ack, syn_urg, syn_res);
//     if (!sendPacket(sock, buffer, &dst, ntohs(ip->tot_len))) {
//         LOGE("TCP doubleSYN 2 first SYN packet failure: %s", strerror(errno));
//         return send_error;
//     }
//     uint32_t seq_local_2 = ntohl(tcp->seq) + 1;
    
//     test_error ret;
//     uint32_t data_read = 0;
    
//     ret = receiveTcpSynAck(seq_local1, sock, ip, tcp, &dst, &src, synack_urg, synack_check, synack_res, data_read);
//     if (ret != success) {
//         LOGE("TCP SYNACK packet failure: %d, %s", ret, strerror(errno));
//         return ret;
//     }
//     // seq_remote = ntohl(tcp->seq) + 1;
//     LOGD("SYNACK \tSeq: %zu \tAck: %zu\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));

    
//     ret = receiveTcpSynAck(seq_local2, sock, ip, tcp, &dst, &src, synack_urg, synack_check, synack_res, data_read);
//     if (ret != success) {
//         LOGE("TCP SYNACK packet failure: %d, %s", ret, strerror(errno));
//         return ret;
//     }
//     // seq_remote = ntohl(tcp->seq) + 1 + datalen;
//     LOGD("SYNACK \tSeq: %zu \tAck: %zu\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
// }
