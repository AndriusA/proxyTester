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
 

#include <chrono>
#include <functional>
#include "util.hpp"
#include "packet_builder.hpp"

const std::chrono::seconds sock_receive_timeout_sec(10);

#ifndef BUFLEN
#define BUFLEN 65535
#endif

#ifndef TAG
#define TAG "TCPTester-bin"
#endif

uint16_t undo_natting(struct iphdr *ip, struct tcphdr *tcp);
uint16_t undo_natting_seq(struct iphdr *ip, struct tcphdr *tcp);

test_error handshake(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                packetModifier fn_synExtras,
                packetFunctor fn_checkTcpSynAck);

test_error shutdownConnection(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote);

test_error sendPacket(int sock, char buffer[], struct sockaddr_in *dst, uint16_t len);

test_error receivePacket(int sock, struct iphdr *ip, struct tcphdr *tcp,
    struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst, uint16_t &length);