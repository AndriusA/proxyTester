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
#include <list>
#include <queue>

#include "tcp_basic.hpp"
#include "util.hpp"

#ifndef TAG
#define TAG "TCPTester-bin"
#endif

#ifndef TESTSUITE
#define TESTSUITE

#ifndef BUFLEN
#define BUFLEN 65535
#endif

test_error setupSocket(int &sock);

// Test sending a specific value in the ACK field of a TCP SYN packet, nothing else changed.
// ACK is set to 0xbeef0001 (opcode), once connection is established, payload contains this value
// IFF the received SYN had ACK set to 0xbeef0001
test_error runTest_ack_only(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);
// The same as above, however URG pointer being 16 bits rather than 32, we only send and expect 0xbe02
test_error runTest_urg_only(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);
// Using ACK field on SYN and URG pointer on SYNACK
// ACK must be 0xbeef0003, SYNACK URG - 0xbe03
test_error runTest_ack_urg(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);
// In our testbed, if there is nothing peculiar about the SYN packet, SYNACK should contain URG pointer
// set to 0xbe04. This is to check if URG pointer without URG flag is allowed through on downlink, since 
// in other cases the uplink packet may be filtered
test_error runTest_plain_urg(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);

test_error runTest_ack_data(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);

// Using ACK field in SYN and setting SYNACK to have specific checksum value (0xbeef) after NATing is nullified
// (subtract destination IP address / port from the value). No other fields are changed to make sure that the
// checksum is correct, so it is very likely not to be.
// ACK set to 0xbeef0005
test_error runTest_ack_checksum_incorrect(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);
// Same as above, but adding 16 bits of payload to make sure that the payload is correct
// ACK set to 0xbeef0006
test_error runTest_ack_checksum(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);
// ACK set to 0xbeef000D
test_error runTest_ack_checksum_incorrect_seq(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);
// Using URG fields both ways, without URG flag set
// Both should be 0xbe07
test_error runTest_urg_urg(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);
// Using URG on SYN and checksum on SYNACK as before
// URG = 0xbe08
test_error runTest_urg_checksum(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);
// URG = 0xbe09
test_error runTest_urg_checksum_incorrect(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);
// Testing whether packets with reserved bits set go through with the bits set during the handshake
// Currently only successful if setting every one of them individually succeeds
test_error runTest_reserved_syn(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port, uint8_t reserved);
// Testing whether packets with reserved bits set go through with the bits set during data transmission/acking
// Currently only successful if setting every one of them individually succeeds
// returns test_complete_complex_bits + bitmap of the passed bits
test_error runTest_reserved_est(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port, uint8_t reserved);

test_error checkTcpSynAck_np(uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res,  
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);
test_error checkTcpSynAck(uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res, 
            char *synack_payload, uint16_t synack_length, 
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);
test_error checkData(char *expect_payload, uint16_t expect_length, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state);

test_error runTest(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port,
            packetModifier fn_synExtras, packetChecker fn_checkTcpSynAck, 
            packetModifier fn_makeRequest, packetChecker fn_checkResponse);
test_error runTest(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port,
            packetModifier fn_synExtras, packetChecker fn_checkTcpSynAck, 
            std::queue<std::pair<packetModifier, packetChecker> > stepSequence);

uint32_t getOwnIp(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port);

#endif


// ISNs new linux kernel: https://lkml.org/lkml/2013/10/5/143
// 		http://lxr.free-electrons.com/source/net/core/secure_seq.c