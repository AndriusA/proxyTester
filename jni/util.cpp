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

void printPacketInfo(struct iphdr *ip, struct tcphdr *tcp) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "TCP Checksum: %04X", ntohs(tcp->check));
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "%s:%i --> ", inet_ntoa(*(struct in_addr*) &ip->saddr), ntohs(tcp->source));
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "\t\t %s:%i", inet_ntoa(*(struct in_addr*) &ip->daddr), ntohs(tcp->dest));
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "\tSeq: %zu \tAck: %zu", ntohl(tcp->seq), ntohl(tcp->ack_seq));
}

void printBufferHex(char *buffer, int length) {
    int i;
    char *buf_str = (char*) malloc(2 * length + 1);
    char *buf_ptr = buf_str;
    for (i = 0; i < length; i++) {
        buf_ptr += sprintf(buf_ptr, "%02X ", buffer[i]);
    }
    *(buf_ptr+1) = '\0';
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "%s", buf_str);
}

uint16_t comp_chksum(uint16_t *addr, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *(addr);
        addr = addr + 1;
        len -= 2;
    }
    if (len > 0) {
        sum += *addr;
    }
    while (sum >> 16) {
        sum = ((sum & 0xffff) + (sum >> 16));
    }
    sum = ~sum;
    return ((uint16_t) sum);
}
