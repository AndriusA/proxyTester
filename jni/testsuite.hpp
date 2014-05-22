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

#ifndef TAG
#define TAG "TCPTester-bin"
#endif

#ifndef TESTSUITE
#define TESTSUITE 1

#define IPHDRLEN sizeof(struct iphdr)
#define TCPHDRLEN sizeof(struct tcphdr)
#define PHDRLEN sizeof(struct pseudohdr)

struct pseudohdr {
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t padding;
    u_int8_t proto;
    u_int16_t length;
};

enum test_error {
    success,
    syn_error,
    synack_error,
    synack_error_urg,
    synack_error_check,
    synack_error_res,
    ack_error,
    send_error,
    invalid_packet,
    receive_error,
    receive_timeout,
    sequence_error,
    protocol_error,
    test_failed,
    test_complete,
    test_not_implemented,
};

static inline uint16_t csum_add(uint16_t csum, uint16_t addend)
{
	uint32_t res = (uint32_t)csum;
	res = res + (uint32_t)addend;
	res = res + ((res >> 16) & 0xFFFF);
	return (uint16_t) res;
}
 
static inline uint16_t csum_sub(uint16_t csum, uint16_t addend)
{
	return csum_add(csum, ~addend);
}

void printBufferHex(char *buffer, int length);
void printPacketInfo(struct iphdr *ip, struct tcphdr *tcp);

test_error runTest_ack_only(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_urg_only(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_ack_urg(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_plain_urg(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_ack_checksum_incorrect(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_ack_checksum(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_urg_urg(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_urg_checksum(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_urg_checksum_incorrect(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_reserved_syn(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);
test_error runTest_reserved_est(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port);

#endif


// ISNs new linux kernel: https://lkml.org/lkml/2013/10/5/143
// 		http://lxr.free-electrons.com/source/net/core/secure_seq.c