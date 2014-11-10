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
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <chrono>

#include "util.hpp"

#define IPHDRLEN sizeof(struct iphdr)
#define TCPHDRLEN sizeof(struct tcphdr)
#define PHDRLEN sizeof(struct pseudohdr)

const std::chrono::seconds sock_receive_timeout_sec(10);

#ifndef BUFLEN
#define BUFLEN 65535
#endif

#ifndef TAG
#define TAG "TCPTester-bin"
#endif

#define TCPWINDOW (BUFLEN - IPHDRLEN - TCPHDRLEN)

struct pseudohdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t padding;
    uint8_t proto;
    uint16_t length;
};

uint16_t undo_natting(struct iphdr *ip, struct tcphdr *tcp);
uint16_t undo_natting_seq(struct iphdr *ip, struct tcphdr *tcp);

test_error handshake(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint32_t syn_ack, uint16_t syn_urg, uint8_t syn_res,
                uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res);
test_error handshake(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint32_t syn_ack, uint16_t syn_urg, uint8_t syn_res,
                uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res,
                char *synack_payload, int synack_length);

test_error shutdownConnection(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote);

test_error sendData(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint8_t data_out_res, char *send_payload, int send_length);

test_error receiveData(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                int &receiveDataLength);

test_error acknowledgeData(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote, int receiveDataLength);

void buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t syn_ack, uint32_t syn_urg, uint8_t syn_res);

void buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t syn_ack, uint32_t syn_urg, uint8_t syn_res,
            uint32_t initial_seq);

test_error receiveTcpSynAck(uint32_t seq_local, int sock, 
            struct iphdr *ip, struct tcphdr *tcp,
            struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst,
            uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res, uint32_t &data_read);

void buildTcpRst(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq, uint32_t ack_seq, uint32_t urg, uint8_t res);

bool sendPacket(int sock, char buffer[], struct sockaddr_in *dst, uint16_t len);