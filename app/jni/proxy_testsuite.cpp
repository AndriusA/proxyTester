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

// TCP handshake function, parametrised with a bunch of values for our testsuite
// 
// param src        source address
// param dst        destination address
// param socket     RAW socket
// param ip         IP header (for reading and writing)
// param tcp        TCP header (for reading and writing)
// param buffer     the whole of the read/write buffer for headers and data
// param seq_local  local sequence number (reference, used for returning the negotiated number)
// param seq_remote remoe sequence number (reference, used for returning the negotiated number)
// param syn_ack    SYN packet ACK value to be sent
// param syn_urg    SYN packet URG pointer to be sent
// param syn_res    SYN packet reserved field value to be sent
// param synack_urg expected SYNACK packet URG pointer value
// param synack_check expected SYNACK packet checksum value (after undoing NATting recalculation)
// param synack_res expected SYNACK packet reserved field value
// return           success if handshake has been successful with all received values matching expected ones,
//                  error code otherwise
test_error handshake_syndata(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint32_t syn_ack, uint16_t syn_urg, uint8_t syn_res,
                uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res,
                char *synack_payload, int synack_length)
{
    test_error ret;
    seq_local = 0;
    seq_remote = 0;
    char send_payload[] = "HELLO_reserved_EST";
    int send_length = strlen(send_payload);
    uint32_t initial_seq = htonl(random() % 65535);
    buildTcpSyn_data(src, dst, ip, tcp, syn_ack, syn_urg, syn_res, initial_seq, send_payload, send_length);
    if (!sendPacket(socket, buffer, dst, ntohs(ip->tot_len))) {
        LOGE("TCP SYN packet failure: %s", strerror(errno));
        return send_error;
    }
    seq_local = ntohl(tcp->seq) + 1;

    // Receive and verify that incoming packet source is our destination and vice-versa
    uint32_t data_read = 0;
    ret = receiveTcpSynAck(seq_local, socket, ip, tcp, dst, src, synack_urg, synack_check, synack_res, data_read);
    if (ret != success) {
        LOGE("TCP SYNACK packet failure: %d, %s", ret, strerror(errno));
        return ret;
    }
    char *data = buffer + IPHDRLEN + TCPHDRLEN;
    int datalen = 0;
    if (synack_length > 0) {
        if (data_read != synack_length) {
            LOGD("SYNACK data_read different than expected");
            return synack_error_data;
        }
        else if (memcmp(data, synack_payload, synack_length) != 0) {
            LOGD("SYNACK data different than expected");
            return synack_error_data;
        }
        LOGD("SYNACK data received as expected");
        datalen = data_read;
    }
    seq_remote = ntohl(tcp->seq) + 1 + datalen;
    LOGD("SYNACK \tSeq: %zu \tAck: %zu\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
    
    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote);
    if (!sendPacket(socket, buffer, dst, ntohs(ip->tot_len))) {
        LOGE("TCP handshake ACK failure: %s", strerror(errno));
        return send_error;
    }
    return success;
}

test_error handshake_ackdata(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint32_t syn_ack, uint16_t syn_urg, uint8_t syn_res,
                uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res,
                char *synack_payload, int synack_length)
{
    test_error ret;
    seq_local = 0;
    seq_remote = 0;
    buildTcpSyn(src, dst, ip, tcp, syn_ack, syn_urg, syn_res);
    if (!sendPacket(socket, buffer, dst, ntohs(ip->tot_len))) {
        LOGE("TCP SYN packet failure: %s", strerror(errno));
        return send_error;
    }
    seq_local = ntohl(tcp->seq) + 1;

    // Receive and verify that incoming packet source is our destination and vice-versa
    uint32_t data_read = 0;
    ret = receiveTcpSynAck(seq_local, socket, ip, tcp, dst, src, synack_urg, synack_check, synack_res, data_read);
    if (ret != success) {
        LOGE("TCP SYNACK packet failure: %d, %s", ret, strerror(errno));
        return ret;
    }
    char *data = buffer + IPHDRLEN + TCPHDRLEN;
    int datalen = 0;
    if (synack_length > 0) {
        if (data_read != synack_length) {
            LOGD("SYNACK data_read different than expected");
            return synack_error_data;
        }
        else if (memcmp(data, synack_payload, synack_length) != 0) {
            LOGD("SYNACK data different than expected");
            return synack_error_data;
        }
        LOGD("SYNACK data received as expected");
        datalen = data_read;
    }
    seq_remote = ntohl(tcp->seq) + 1 + datalen;
    LOGD("SYNACK \tSeq: %zu \tAck: %zu\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
    
    char send_payload[] = "HELLO_reserved_EST";
    int send_length = strlen(send_payload);
    if (!sendData(src, dst, socket, ip, tcp, buffer, seq_local, seq_remote, 0, send_payload, send_length)) {
        LOGE("TCP handshake ACK failure: %s", strerror(errno));
        return send_error;
    }
    int receiveLength;
    if (receiveData(src, dst, socket, ip, tcp, buffer, seq_local, seq_remote, receiveLength) == success) {
        if (receiveLength > 0) {
            acknowledgeData(src, dst, socket, ip, tcp, buffer, seq_local, seq_remote, receiveLength);
        }
    }
    return success;
}

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

void *threadedHandshake_syndata(void *threadarg) {
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
    int result = handshake_syndata(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, 
        syn_ack, syn_urg, syn_res, 
        synack_urg, synack_check, synack_res, NULL, 0);
    LOGD("Thread %d handshake result: %d", d->thread_id, result);
    pthread_exit((void*) result);
}

void *threadedHandshake_ackdata(void *threadarg) {
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
    int result = handshake_ackdata(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, 
        syn_ack, syn_urg, syn_res, 
        synack_urg, synack_check, synack_res, NULL, 0);
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
    char buffer_3[BUFLEN] = {0};
    struct iphdr *ip_1, *ip_2, *ip_3;
    struct tcphdr *tcp_1, *tcp_2, *tcp_3;
    struct sockaddr_in src, dst, src2, src3;
    uint32_t seq_local_1, seq_remote_1, seq_local_2, seq_remote_2, seq_local_3, seq_remote_3;
    ip_1 = (struct iphdr*) buffer_1;
    ip_2 = (struct iphdr*) buffer_2;
    ip_3 = (struct iphdr*) buffer_3;
    tcp_1 = (struct tcphdr*) (buffer_1 + IPHDRLEN);
    tcp_2 = (struct tcphdr*) (buffer_2 + IPHDRLEN);
    tcp_3 = (struct tcphdr*) (buffer_3 + IPHDRLEN);
    char *data_1 = buffer_1 + IPHDRLEN + TCPHDRLEN;
    char *data_2 = buffer_2 + IPHDRLEN + TCPHDRLEN;
    char *data_3 = buffer_3 + IPHDRLEN + TCPHDRLEN;

    src.sin_family = AF_INET;
    src.sin_port = htons(src_port);
    src.sin_addr.s_addr = htonl(source);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = htonl(destination);
    src2.sin_family = AF_INET;
    src2.sin_port = htons(src_port+1);
    src2.sin_addr.s_addr = htonl(source);
    src3.sin_family = AF_INET;
    src3.sin_port = htons(src_port+2);
    src3.sin_addr.s_addr = htonl(source);

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

    data_hs3 = data_hs1;
    data_hs3.thread_id = 3;
    data_hs3.buffer = &buffer_3[0];
    data_hs3.src = src3;

    LOGD("Starting handshake threads");
    pthread_t thread_hs1, thread_hs2, thread_hs3;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    int rc_hs1 = pthread_create(&thread_hs1, &attr, threadedHandshake, (void *) &data_hs1);
    int rc_hs2 = pthread_create(&thread_hs2, &attr, threadedHandshake, (void *) &data_hs2);
    // int rc_hs3 = pthread_create(&thread_hs3, &attr, threadedHandshake, (void *) &data_hs3);

    pthread_attr_destroy(&attr);
    void *status;
    LOGD("Waiting for both handshakes");
    rc_hs1 = pthread_join(thread_hs1, &status);
    rc_hs2 = pthread_join(thread_hs2, &status);
    // rc_hs3 = pthread_join(thread_hs3, &status);

    test_error result = success;
    LOGD("Sleeping, then RSTing middle connection");
    sleep(10);
    LOGD("Build TCP RST");

    buildTcpAck(&src, &dst, ip_1, tcp_1, tcp_1->seq, tcp_1->ack_seq);
    tcp_1->window = 0;
    if (!sendPacket(sock, buffer_1, &dst, ntohs(ip_1->tot_len))) {
        LOGE("TCP handshake ACK failure: %s", strerror(errno));
        return send_error;
    }

    // char send_payload_rst[] = "CONNECTION_RESET_BY_PEER";
    // int send_length_rst = strlen(send_payload_rst);
    // buildTcpRst_data(&src2, &dst, ip_2, tcp_2, ntohl(tcp_2->seq), ntohl(tcp_2->ack_seq), 0, 0, send_payload_rst, send_length_rst);
    // LOGD("Send TCP RST");
    // if (!sendPacket(sock, buffer_2, &dst, ntohs(ip_2->tot_len))) {
    //     LOGE("TCP doubleSYN RST failure: %s", strerror(errno));
    //     result = send_error;
    // }
    LOGD("Cycle done");
    sleep(5);
    LOGD("Testing finished, returning");
    return result;
}

// Encode 
test_error runTest_sackGap(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port) {
    // Packet fields
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;    
    char expect_payload[] = "";
    int expect_length = 0;
    char synack_payload[] = "";
    int synack_length = 0;

    // Socket data initialisation
    int sock;
    char buffer[BUFLEN] = {0};
    
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct sockaddr_in src, dst;
    uint32_t seq_local, seq_remote;
    ip = (struct iphdr*) buffer;
    tcp = (struct tcphdr*) (buffer + IPHDRLEN);
    char *data = buffer + IPHDRLEN + TCPHDRLEN;

    src.sin_family = AF_INET;
    src.sin_port = htons(src_port);
    src.sin_addr.s_addr = htonl(source);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = htonl(destination);

    // Socket setup
    if (setupSocket(sock) != success) {
        LOGE("Socket setup failed: %s", strerror(errno));
        return test_failed;
    } else {
        LOGD("Socket setup, initialising data");
    }

    seq_local = 0;
    seq_remote = 0;

    buildTcpSyn(&src, &dst, ip, tcp, syn_ack, syn_urg, syn_res);
    // Append SACK OK option
    appendTcpOption(ip, tcp, 0x04, 0x02, NULL);
    if (!sendPacket(sock, buffer, &dst, ntohs(ip->tot_len))) {
        LOGE("TCP SYN packet failure: %s", strerror(errno));
        return send_error;
    }

    seq_local = ntohl(tcp->seq) + 1;

    // Receive and verify that incoming packet source is our destination and vice-versa
    uint32_t data_read = 0;
    test_error ret = receiveTcpSynAck(seq_local, sock, ip, tcp, &dst, &src, synack_urg, synack_check, synack_res, data_read);
    if (ret != success) {
        LOGE("TCP SYNACK packet failure: %d, %s", ret, strerror(errno));
        return ret;
    }

    int datalen = 0;
    if (synack_length > 0) {
        if (data_read != synack_length) {
            LOGD("SYNACK data_read different than expected");
            return synack_error_data;
        }
        else if (memcmp(data, synack_payload, synack_length) != 0) {
            LOGD("SYNACK data different than expected");
            return synack_error_data;
        }
        LOGD("SYNACK data received as expected");
        datalen = data_read;
    }
    seq_remote = ntohl(tcp->seq) + 1 + datalen;
    LOGD("SYNACK \tSeq: %zu \tAck: %zu\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
    
    char send_payload[] = "HELLO_ACK_GAP";
    int send_length = strlen(send_payload);
    uint32_t seq_local_sent = seq_local + 0xbe;
    if (!sendData(&src, &dst, sock, ip, tcp, buffer, seq_local_sent, seq_remote, 0, send_payload, send_length)) {
        LOGE("TCP handshake ACK failure: %s", strerror(errno));
        return send_error;
    }
    int receiveLength;
    if (receiveData(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, receiveLength) == success) {
        if (receiveLength > 0) {
            acknowledgeData(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, receiveLength);
        }
    }
    return success;
}
