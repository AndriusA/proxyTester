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
#include "packet_builder.hpp"

void concatPacketModifiers(packetModifier a, packetModifier b, 
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state)
{
    a(ip, tcp, conn_state);
    b(ip, tcp, conn_state);
}

test_error concatPacketCheckers(packetChecker a, packetChecker b, 
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state)
{
    test_error ret;
    ret = a(ip, tcp, conn_state);
    if (ret == success)
        ret = b(ip, tcp, conn_state);
    return ret;
}

void buildIPHeader(struct iphdr *ip, 
            uint32_t source, uint32_t destination,
            uint32_t data_length)
{
    ip->frag_off    = 0;
    ip->version     = 4;
    ip->ihl         = 5;
    ip->tot_len     = htons(IPHDRLEN + TCPHDRLEN + data_length);
    ip->id          = 0;
    ip->ttl         = 40;
    ip->protocol    = IPPROTO_TCP;
    ip->saddr       = source;
    ip->daddr       = destination;
    ip->check       = 0;
}

// Computes checksum of a TCP packet by creating a pseudoheader
// from provided IP packet and appending it after the payload.
// Since the checksum is a one's complement, 16-bit sum, appending
// or prepending has no difference other than having to be careful
// to add one zero-padding byte after data if length is not even
uint16_t tcpChecksum(struct iphdr *ip, struct tcphdr *tcp) {
    // Add pseudoheader at the end of the packet for simplicity,
    struct pseudohdr *pseudoheader;
    // Need to add padding between data and pseudoheader
    // if data payload length is not a multiple of 2,
    // checksum is a 2 byte value.
    uint8_t tcphdrlen = tcp->doff * 4;
    int datalen = ntohs(ip->tot_len) - IPHDRLEN - tcphdrlen;
    int padding = datalen % 2 ? 1 : 0;
    pseudoheader = (struct pseudohdr *) ( (uint8_t *) tcp + tcphdrlen + datalen + padding );
    pseudoheader->src_addr = ip->saddr;
    pseudoheader->dst_addr = ip->daddr;
    pseudoheader->padding = 0;
    pseudoheader->proto = ip->protocol;
    pseudoheader->length = htons(tcphdrlen + datalen);
    // LOGD("Checksum over (len %d, datalen %d)", tcphdrlen + datalen + padding + PHDRLEN, datalen);
    // printBufferHex((char*)tcp, tcphdrlen + datalen + padding + PHDRLEN);
    // compute chekcsum from the bound of the tcp header to the appended pseudoheader
    uint16_t checksum = comp_chksum((uint16_t*) tcp,
            tcphdrlen + datalen + padding + PHDRLEN);
    return checksum;
}

void recomputeTcpChecksum(struct iphdr *ip, struct tcphdr *tcp) {
    tcp->check = 0;
    tcp->check = tcpChecksum(ip, tcp);
}

void appendData(char data[], uint16_t datalen, struct iphdr *ip, struct tcphdr *tcp) {
    LOGD("Appending %d bytes of TCP data", datalen);
    char *dataStart = (char*) ip + IPHDRLEN + (tcp->doff * 4);
    memset(dataStart, 0, BUFLEN - (IPHDRLEN + (tcp->doff * 4)));
    memcpy(dataStart, data, datalen);
    ip->tot_len = htons(ntohs(ip->tot_len) + datalen);
    tcp->psh = 1;
    recomputeTcpChecksum(ip, tcp);
}

void tcpZeroFlags(struct tcphdr *tcp) {
    tcp->ack = 0;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->urg = 0;
    tcp->syn = 0;
    tcp->fin = 0;
}

void tcpDefaultFields(struct tcphdr *tcp, uint16_t source, uint16_t dest, uint32_t seq)
{
    tcp->source     = source;
    tcp->dest       = dest;
    tcp->seq        = htonl(seq);
    tcp->ack_seq    = htonl(0);
    tcp->res1       = 0;            
    tcp->doff       = 5;                // Data offset 5 octets (no options)
    tcp->window     = htons(TCPWINDOW);
    tcp->urg_ptr    = 0;
}

// Build a TCP/IP SYN packet with the given
// ACK number, URG pointer and reserved field values
// Packet is pass-by-reference, new values stored there
void buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp) 
{
    uint32_t initial_seq = htonl(random() % 65535);
    buildTcpSyn(src, dst, ip, tcp, initial_seq);
}
void buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp, uint32_t seq) 
{
    // IP packet with TCP and no payload
    int datalen = 0;
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);
    tcpDefaultFields(tcp, src->sin_port, dst->sin_port, seq);
    tcpZeroFlags(tcp);
    tcp->syn        = 1;
    recomputeTcpChecksum(ip, tcp);
}

void addSynExtras(uint32_t syn_ack, uint32_t syn_urg, uint8_t syn_res,
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state)
{
    tcp->res1       = syn_res & 0xF;            // 4 bits reserved field
    tcp->urg_ptr    = htons(syn_urg);
    tcp->ack_seq    = htonl(syn_ack);
    recomputeTcpChecksum(ip, tcp);
} 

void buildTcpRst(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq, uint32_t ack_seq, uint32_t urg, uint8_t res)
{
    // IP packet with TCP and no payload
    int datalen = 0;
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);
    tcpDefaultFields(tcp, src->sin_port, dst->sin_port, seq);
    tcpZeroFlags(tcp);
    tcp->rst        = 1;
    tcp->res1       = res & 0xF;            // 4 bits reserved field
    tcp->urg_ptr    = htons(urg);
    tcp->ack_seq    = htonl(ack_seq);
    recomputeTcpChecksum(ip, tcp);
}


// Build a TCP/IP ACK packet with the given
// sequence numbers, everything else as standard, valid TCP
void buildTcpAck(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq, uint32_t ack_seq,
            uint8_t reserved) 
{
    int datalen = 0;
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);
    tcpDefaultFields(tcp, src->sin_port, dst->sin_port, seq);
    tcpZeroFlags(tcp);
    tcp->ack        = 1;
    tcp->ack_seq    = htonl(ack_seq);
    recomputeTcpChecksum(ip, tcp);
}   
void buildTcpAck(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq_local, uint32_t seq_remote) 
{
    uint8_t reserved = 0;
    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote, reserved);
}

// Build a TCP/IP FIN packet with the given
// sequence numbers, everything else as standard, valid TCP
void buildTcpFin(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq_local, uint32_t seq_remote) 
{
    // IP packet with TCP and no payload
    int datalen = 0;
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);
    tcpDefaultFields(tcp, src->sin_port, dst->sin_port, seq_local);
    tcpZeroFlags(tcp);
    tcp->ack = 1;
    tcp->fin = 1;
    tcp->ack_seq = htonl(seq_remote);
    recomputeTcpChecksum(ip, tcp);
}

void appendTcpOption(uint8_t option_kind, uint8_t option_length, char option_data[],
            struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state)
{
    LOGD("Appending TCP option %02X", option_kind);
    // Find the length of data in the packet - total packet length, 
    // minus IP header and tcp header length through daa offset
    uint8_t data_offset = tcp->doff * 4;
    int datalen = ntohs(ip->tot_len) - IPHDRLEN - data_offset;
    // Will add NOP options for alignment
    uint8_t nops = ((option_length / 4) + 1) * 4 - option_length;
    // This is where the data starts
    char *dataStart = (char*) ip + IPHDRLEN + data_offset;
    // Once the data is moved, the appended option will start here
    char *optionStart = dataStart;
    if (datalen > 0) {    
        // Move all the data by the option length
        memmove(dataStart, dataStart + nops + option_length, datalen);
    }
    // Increase packet length
    ip->tot_len = htons(ntohs(ip->tot_len) + nops + option_length);
    tcp->doff = tcp->doff + (nops + option_length) / 4;

    memset(optionStart, TCPOPT_NOP, nops);
    *(optionStart + nops) = (char) option_kind;
    if (option_length >= 2) {
        *(optionStart + nops + 1) = (char) option_length;
        if (option_length > 2) {
            memcpy(optionStart + nops + 2, option_data, option_length - 2);
        }
    }

    recomputeTcpChecksum(ip, tcp);
}

test_error hasTcpOption(uint8_t option_kind, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state) {
    uint8_t *currentOption = (uint8_t*) ip + IPHDRLEN + TCPHDRLEN;
    uint8_t optionOffset = 0;
    bool optionFound = false;
    uint8_t optionsLength = tcp->doff * 4 - TCPHDRLEN;
    // Iterate through all the options, looking for the current one
    while (optionOffset < optionsLength) {
        uint8_t c_option_kind = *(currentOption + optionOffset);
        // End of Option List
        if (c_option_kind == 0)
            break;
        // NOP
        if (c_option_kind == 1) {
            optionOffset++;
            continue;
        }
        if (c_option_kind == option_kind) {
            optionFound = true;
            break;
        }
        uint8_t c_optionOffset = *(currentOption + optionOffset + 1);
        optionOffset = optionOffset + c_optionOffset + 1;
    }
    if (optionFound) {
        if (option_kind == TCPOPT_SACK)
            conn_state->sack_ok = true;
        if (option_kind == TCPOPT_TIMESTAMP) {
            conn_state->tstamp_ok = true;
            uint32_t TSval = 0;
            TSval = ntohl(*(uint32_t *) (currentOption + optionOffset + 1 + 1));
            // FIXME: rcv_nxt not completely correct
            // should be SEG.TSval >= TS.Recent and SEG.SEQ <= Last.ACK.sent
            LOGD("Check for timestamp: %u, seq %u", TSval, ntohl(tcp->seq));
            if ((TSval >= conn_state->ts_recent && ntohl(tcp->seq) <= conn_state->rcv_nxt-1) || tcp->syn) {
                conn_state->ts_recent = TSval;
                LOGD("New ts_recent %u", conn_state->ts_recent);
            }
        }
        return success;
    }
    else {
        if (option_kind == TCPOPT_SACK)
            conn_state->sack_ok = false;
        if (option_kind == TCPOPT_TIMESTAMP)
            conn_state->tstamp_ok = false;
        return option_not_found;
    }
}

void setRes(uint8_t res, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state) {
    tcp->res1 = (res & 0xF);
    recomputeTcpChecksum(ip, tcp);
}

void increaseSeq(uint32_t increase, struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state) {
    tcp->seq = htonl(ntohl(tcp->seq) + increase);
    recomputeTcpChecksum(ip, tcp);
}


void appendSackBlock(struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state)
{
    if (!conn_state->sack_ok)
        return;
    conn_state->eff_sacks = conn_state->num_sacks;
    if (conn_state->eff_sacks > 0)
        appendTcpOption(TCPOPT_SACK, (uint8_t)(0x02 + conn_state->eff_sacks * 4 * 2), (char*) (conn_state->selective_acks), ip, tcp, conn_state);
}

void appendTimestamp(struct iphdr *ip, struct tcphdr *tcp, struct tcp_opt *conn_state)
{
    if (!conn_state->tstamp_ok)
        return;
    char optionData[8];
    uint32_t tsval = htonl(conn_state->rcv_tsval);
    uint32_t tsrecent = htonl(conn_state->ts_recent);
    memcpy(optionData, &tsval, sizeof(tsval));
    memcpy(optionData+sizeof(conn_state->rcv_tsval), &tsrecent, sizeof(tsrecent));
    appendTcpOption(TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP, optionData, ip, tcp, conn_state);
}

void removeSackBlock(int block, struct tcp_opt *conn_state) {
    // Remove this element by shifting others
    for (int j = block+1; j < conn_state->num_sacks; block++) {
        conn_state->selective_acks[j-1].start_seq = conn_state->selective_acks[j].start_seq;
        conn_state->selective_acks[j-1].end_seq = conn_state->selective_acks[j].end_seq;
    }
    conn_state->num_sacks--;
    // Zero the rest
    int arrlen = sizeof(conn_state->selective_acks) / sizeof(conn_state->selective_acks[0]);
    for (int j = conn_state->num_sacks; j < arrlen; j++) {
        conn_state->selective_acks[j].start_seq = 0;
        conn_state->selective_acks[j].end_seq = 0;
    }
}

void insertSackBlock(tcp_sack_block block, struct tcp_opt *conn_state) {
    int arrlen = sizeof(conn_state->selective_acks) / sizeof(conn_state->selective_acks[0]);
    if (conn_state->num_sacks < arrlen) {
        int pos = 0;
        while (block.start_seq > conn_state->selective_acks[pos].start_seq && pos < conn_state->num_sacks) {
            pos++;
        }
        for (int i = pos; i < arrlen - 1; i++) {
            conn_state->selective_acks[i+1].start_seq = conn_state->selective_acks[i].start_seq;
            conn_state->selective_acks[i+1].end_seq = conn_state->selective_acks[i].end_seq;
        }
        conn_state->selective_acks[pos].start_seq = block.start_seq;
        conn_state->selective_acks[pos].end_seq = block.end_seq;
    }
}