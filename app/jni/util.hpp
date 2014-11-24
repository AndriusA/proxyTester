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

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdlib.h>
#include <cstdio>
#include <android/log.h>

#ifndef UTIL
#define UTIL

#ifndef TAG
#define TAG "TCPTester-bin"
#endif

// #define LOGD(...)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
// #define LOGE(...)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

enum test_error {
    success,
    response_acceptable,
    syn_error,
    synack_error,
    synack_error_urg,
    synack_error_check,
    synack_error_res,
    synack_error_data,
    synack_error_data_length,
    ack_error,
    send_error,
    rst_send_error,
    invalid_packet,
    receive_error,
    receive_error_data,
    receive_error_data_length,
    receive_error_data_value,
    receive_error_res_value,
    option_not_found,
    receive_timeout,
    sequence_error,
    protocol_error,
    test_failed,
    test_complete,
    test_not_implemented
};

void printPacketInfo(struct iphdr *ip, struct tcphdr *tcp);
void printBufferHex(char *buffer, int length);
uint16_t comp_chksum(uint16_t *addr, int len);
uint16_t csum_add(uint16_t csum, uint16_t addend);
uint16_t csum_sub(uint16_t csum, uint16_t addend);

#endif