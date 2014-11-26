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
#include <functional>

#include "tcp_opt.h"
#include "util.hpp"

#define IPHDRLEN sizeof(struct iphdr)
#define TCPHDRLEN sizeof(struct tcphdr)
#define PHDRLEN sizeof(struct pseudohdr)

#ifndef TAG
#define TAG "TCPTester-bin"
#endif

#ifndef BUFLEN
#define BUFLEN 65535
#endif

#define TCPWINDOW (BUFLEN - IPHDRLEN - TCPHDRLEN)

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MAXSEG 2
#define TCPOLEN_MAXSEG 4
#define TCPOPT_WINDOW 3
#define TCPOLEN_WINDOW 3
#define TCPOPT_SACK_PERMITTED 4
#define TCPOLEN_SACK_PERMITTED 2
#define TCPOPT_SACK 5                                                                                                                                                                                   
#define TCPOPT_TIMESTAMP 8
#define TCPOLEN_TIMESTAMP 10
#define TCPOLEN_TSTAMP_APPA (TCPOLEN_TIMESTAMP+2)

#define TCPOPT_TSTAMP_HDR (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)


struct pseudohdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t padding;
    uint8_t proto;
    uint16_t length;
};

typedef std::function< test_error(struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state) > packetChecker;
typedef std::function< void(struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state) > packetModifier;
void concatPacketModifiers(packetModifier a, packetModifier b, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);
test_error concatPacketCheckers(packetChecker a, packetChecker b, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);

void buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp);

void buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp, uint32_t seq);

void addSynExtras(uint32_t syn_ack, uint32_t syn_urg, uint8_t syn_res,
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);

void appendTcpOption(uint8_t option_kind, uint8_t option_length, char option_data[],
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);

test_error hasTcpOption(uint8_t option_kind, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);

void appendData(char data[], uint16_t datalen, struct iphdr *ip, struct tcphdr *tcp);


void buildTcpRst(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq, uint32_t ack_seq, uint32_t urg, uint8_t res);

void buildTcpAck(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq, uint32_t ack_seq);

void buildTcpAck(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq, uint32_t ack_seq,
            uint8_t reserved);

void buildTcpFin(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq_local, uint32_t seq_remote);

void setRes(uint8_t res, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);
void increaseSeq(uint32_t increase, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);

void appendTimestamp(struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);
void appendSackBlock(struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);
void removeSackBlock(int block, struct tcp_opt *conn_state);
void insertSackBlock(tcp_sack_block block, struct tcp_opt *conn_state);