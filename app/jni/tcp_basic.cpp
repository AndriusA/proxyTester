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
#include "tcp_basic.hpp"

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
uint16_t tcpChecksum(struct iphdr *ip, struct tcphdr *tcp, int datalen) {
    // Add pseudoheader at the end of the packet for simplicity,
    struct pseudohdr * pseudoheader;
    // Need to add padding between data and pseudoheader
    // if data payload length is not a multiple of 2,
    // checksum is a 2 byte value.
    int padding = datalen % 2 ? 1 : 0;
    pseudoheader = (struct pseudohdr *) ( (uint8_t *) tcp + (tcp->doff*4) + datalen + padding );
    pseudoheader->src_addr = ip->saddr;
    pseudoheader->dst_addr = ip->daddr;
    pseudoheader->padding = 0;
    pseudoheader->proto = ip->protocol;
    pseudoheader->length = htons((tcp->doff*4) + datalen);
    // compute chekcsum from the bound of the tcp header to the appended pseudoheader
    uint16_t checksum = comp_chksum((uint16_t*) tcp,
            (tcp->doff*4) + datalen + padding + PHDRLEN);
    return checksum;
}

// Function very specific to our tests and relies on packet checksum
// being computed in a specific way:
//      - The sending side decides the target checksum value
//      - Subtracts the destination IP address and port from that value
//      - If there is an intermediate NAT, it hopefully only modifies
//        the destination port and/or address and recomputes checksum
//        according to RFC3022
//      - It is sufficient to add back the (potentially new) destination address
//        to the received checksum to obtain the sender's target one
uint16_t undo_natting(struct iphdr *ip, struct tcphdr *tcp) {
    uint32_t checksum = ntohs(tcp->check);
    // Add back destination (own!) IP address and port number to undo what NAT modifies
    checksum = csum_add(checksum, ntohs(ip->daddr & 0xFFFF));
    checksum = csum_add(checksum, ntohs((ip->daddr >> 16) & 0xFFFF));
    checksum = csum_add(checksum, ntohs(tcp->dest));
    LOGD("Checksum NATing recalculated: %d, %04X", checksum, checksum);
    return (uint16_t) checksum;
}
uint16_t undo_natting_seq(struct iphdr *ip, struct tcphdr *tcp) {
    uint32_t checksum = ntohs(tcp->check);
    // Add back destination (own!) IP address and port number to undo what NAT modifies
    checksum = csum_add(checksum, ntohs(ip->daddr & 0xFFFF));
    checksum = csum_add(checksum, ntohs((ip->daddr >> 16) & 0xFFFF));

    checksum = csum_add(checksum, ntohs(tcp->dest));

    checksum = csum_add(checksum, ntohs(tcp->seq & 0xFFFF));
    checksum = csum_add(checksum, ntohs((tcp->seq >> 16) & 0xFFFF));
    checksum = csum_add(checksum, ntohs(tcp->ack_seq & 0xFFFF));
    checksum = csum_add(checksum, ntohs((tcp->ack_seq >> 16) & 0xFFFF));
    
    LOGD("Checksum NATing recalculated (Seq): %d, %04X", checksum, checksum);
    return (uint16_t) checksum;
}

// Check if the received packet is a valid one:
// the IP addresses and port numbers match the expected ones.
// We are using RAW sockets, which get a copy all incoming TCP traffic,
// so we need to filter out the packets that are not for us.
//
// param ip         IP header
// param tcp        TCP header
// param exp_src    expected packet source address (IP and port)
// param exp_dst    expected packet destination address (IP and port)
// return           true or false
bool validPacket(struct iphdr *ip, struct tcphdr *tcp,
    struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst)
{
    if ( ip->saddr != exp_src->sin_addr.s_addr || ip->daddr != exp_dst->sin_addr.s_addr ) {
        // LOGE("Corrupted packet received: unexpected IP address");
        return false;
    } else if ( tcp->source != exp_src->sin_port || tcp->dest != exp_dst->sin_port ) {
        // LOGE("Corrupted packet received: unexpected port number");
        return false;
    } else {
        return true;
    }
}

// Receive one packet from the given socket.
// Blocks until there is a valid packet matching the expected connection
// or until recv fails (e.g. times out or the socket is closed).
//
// TODO: better logic for packet receive failure - currently could wait for a long
// time until recv fails (times out) if there is other TCP traffic
//
// param sock       The socket
// param ip         IP header
// param tcp        TCP header
// param exp_src    expected packet source address (IP and port)
// param exp_dst    expected packet destination address (IP and port)
// return           length of the packet read or -1 if recv returned -1
int receivePacket(int sock, struct iphdr *ip, struct tcphdr *tcp,
    struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst)
{
    std::chrono::time_point<std::chrono::system_clock> start, now;
    start = std::chrono::system_clock::now();
    while (true) {
        int length = recv(sock, (char*)ip, BUFLEN, 0);
        // LOGD("Received %d bytes \n", length);
        // Error reading from socket or reading timed out - failure either way
        if (length == -1) {
            return length;
        }

        if (validPacket(ip, tcp, exp_src, exp_dst)) {
            // printPacketInfo(ip, tcp);
            // printBufferHex((char*)ip, length);
            return length;
        }
        else {
            // Read a packet that belongs to some other connection
            // try again unless we have exceeded receive timeout
            now = std::chrono::system_clock::now();
            if (now - start > sock_receive_timeout_sec) {
                LOGD("Packet reading timed out");
                return -1;
            }
        }
    }
}

bool sendPacket(int sock, char buffer[], struct sockaddr_in *dst, uint16_t len) {
    int bytes = sendto(sock, buffer, len, 0, (struct sockaddr*) dst, sizeof(*dst));
    if (bytes == -1) {
        LOGE("sendto() failed for data packet: %s", strerror(errno));
        return false;
    }
    return true;
}

// Function to receive SYNACK packet of TCP's three-way handshake.
// Wraps the normal receivePacket function call with SYNACK specific logic,
// checking for the right flags, sequence numbers and our testsuite-specific
// checks for the right values in the different parts of the header.
//
// param seq_local      local sequence number (check against ack)
// param sock           socket to receive synack from
// param ip             IP header
// param tcp            TCP header
// param exp_src        expected source address (remote!)
// param exp_dst        expected destination address (local!)
// param synack_urg     expected UGR pointer value
// param synack_check   expected checksum value (after running undo_natting)
// param synack_res     expected reserved field value
// return               execution status - success or a number of possible errors
test_error receiveTcpSynAck(uint32_t seq_local, int sock, 
            struct iphdr *ip, struct tcphdr *tcp,
            struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst,
            uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res, uint32_t &data_read)
{
    int packet_length = receivePacket(sock, ip, tcp, exp_src, exp_dst);
    if (packet_length < 0) {
        LOGE("SYNACK packet receive length < 0");
        return receive_error;
    }
    if (packet_length >= IPHDRLEN + TCPHDRLEN)
        data_read = packet_length - IPHDRLEN - TCPHDRLEN;
    if (!tcp->syn || !tcp->ack) {
        LOGE("Not a SYNACK packet");
        return protocol_error;
    }
    if (seq_local != ntohl(tcp->ack_seq)) {
        LOGE("SYNACK packet unexpected ACK number: %u, %u", seq_local, ntohl(tcp->ack_seq));
        return sequence_error;
    }
    if (synack_urg != 0 && ntohs(tcp->urg_ptr) != synack_urg) {
        LOGE("SYNACK packet expected urg %04X, got: %04X", synack_urg, ntohs(tcp->urg_ptr));
        return synack_error_urg;
    }
    if (synack_check != 0) {
        uint16_t check = undo_natting(ip, tcp);
        uint16_t check2 = undo_natting_seq(ip, tcp);
        if (synack_check != check && synack_check != check2) {
            LOGE("SYNACK packet expected check %04X, got: %04X or %04X", synack_check, check, check2);
            return synack_error_check;
        }
    }
    if (synack_res != 0 && synack_res != (tcp->res1 & 0xF) ) {
        LOGE("SYNACK packet expected res %02X, got: %02X", synack_res, (tcp->res1 & 0xF));
        return synack_error_res;
    }
    
    return success;
}

// Build a TCP/IP SYN packet with the given
// ACK number, URG pointer and reserved field values
// Packet is pass-by-reference, new values stored there
void buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t syn_ack, uint32_t syn_urg, uint8_t syn_res) 
{
    uint32_t initial_seq = htonl(random() % 65535);
    buildTcpSyn(src, dst, ip, tcp, syn_ack, syn_urg, syn_res, initial_seq);
}
void buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t syn_ack, uint32_t syn_urg, uint8_t syn_res,
            uint32_t initial_seq) 
{
    // IP packet with TCP and no payload
    int datalen = 0;
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);

    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(initial_seq);
    tcp->ack_seq    = htonl(syn_ack);
    tcp->res1       = syn_res & 0xF;            // 4 bits reserved field
    tcp->doff       = 5;                        // Data offset 5 octets (no options)
    tcp->ack        = 0;
    tcp->psh        = 0;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 1;
    tcp->fin        = 0;
    tcp->window     = htons(TCPWINDOW);
    tcp->urg_ptr    = htons(syn_urg);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
    // printPacketInfo(ip, tcp);
}

void buildTcpSyn_data(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t syn_ack, uint32_t syn_urg, uint8_t syn_res,
            uint32_t initial_seq,
            char data[], int datalen) 
{
    // IP packet with TCP and no payload
    char *dataStart = (char*) ip + IPHDRLEN + TCPHDRLEN;
    memcpy(dataStart, data, datalen);
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);

    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(initial_seq);
    tcp->ack_seq    = htonl(syn_ack);
    tcp->res1       = syn_res & 0xF;            // 4 bits reserved field
    tcp->doff       = 5;                        // Data offset 5 octets (no options)
    tcp->ack        = 0;
    tcp->psh        = 0;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 1;
    tcp->fin        = 0;
    tcp->window     = htons(TCPWINDOW);
    tcp->urg_ptr    = htons(syn_urg);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
    // printPacketInfo(ip, tcp);
}

void buildTcpRst(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq, uint32_t ack_seq, uint32_t urg, uint8_t res)
{
    // IP packet with TCP and no payload
    int datalen = 0;
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);
    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(seq);
    tcp->ack_seq    = htonl(ack_seq);
    tcp->res1       = res & 0xF;            // 4 bits reserved field
    tcp->doff       = 5;                        // Data offset 5 octets (no options)
    tcp->ack        = 0;
    tcp->psh        = 0;
    tcp->rst        = 1;
    tcp->urg        = 0;
    tcp->syn        = 0;
    tcp->fin        = 0;
    tcp->window     = htons(TCPWINDOW);
    tcp->urg_ptr    = htons(urg);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
}
void buildTcpRst_data(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq, uint32_t ack_seq, uint32_t urg, uint8_t res,
            char data[], int datalen)
{
    // IP packet with TCP and no payload
    char *dataStart = (char*) ip + IPHDRLEN + TCPHDRLEN;
    memcpy(dataStart, data, datalen);
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);
    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(seq);
    tcp->ack_seq    = htonl(ack_seq);
    tcp->res1       = res & 0xF;            // 4 bits reserved field
    tcp->doff       = 5;                        // Data offset 5 octets (no options)
    tcp->ack        = 0;
    tcp->psh        = 0;
    tcp->rst        = 1;
    tcp->urg        = 0;
    tcp->syn        = 0;
    tcp->fin        = 0;
    tcp->window     = htons(TCPWINDOW);
    tcp->urg_ptr    = htons(urg);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
}

// Build a TCP/IP ACK packet with the given
// sequence numbers, everything else as standard, valid TCP
void buildTcpAck(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq_local, uint32_t seq_remote) 
{
    int datalen = 0;
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);

    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(seq_local);
    tcp->ack_seq    = htonl(seq_remote);
    tcp->doff       = 5;
    tcp->ack        = 1;
    tcp->psh        = 0;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 0;
    tcp->fin        = 0;
    tcp->window     = htons(TCPWINDOW);
    tcp->urg_ptr    = 0;
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
    // printPacketInfo(ip, tcp);
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

    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(seq_local);
    tcp->ack_seq    = htonl(seq_remote);
    tcp->doff       = 5;    // Data offset 5 octets (no options)
    tcp->ack        = 1;
    tcp->psh        = 0;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 0;
    tcp->fin        = 1;
    tcp->window     = htons(TCPWINDOW);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
    // printPacketInfo(ip, tcp);
}

// Build a TCP/IP data packet with the given
// sequence numbers, reserved field value and data
//
// param src        Source address
// param dst        Destination address
// param ip         IP header
// param tcp        TCP header
// param seq_local  local sequence number
// param seq_remote remote sequence number
// param reserved   reserved field value
// param data       byte array of data
// param datalen    length of data to be sent
void buildTcpData(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq_local, uint32_t seq_remote,
            uint8_t reserved,
            char data[], int datalen)
{
    char *dataStart = (char*) ip + IPHDRLEN + TCPHDRLEN;
    memcpy(dataStart, data, datalen);
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);

    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(seq_local);
    tcp->ack_seq    = htonl(seq_remote);
    tcp->res1       = reserved & 0xF;
    tcp->doff       = 5;
    tcp->ack        = 1;
    tcp->psh        = (datalen > 0 ? 1 : 0);
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 0;
    tcp->fin        = 0;
    tcp->window     = htons(TCPWINDOW);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);

    // printPacketInfo(ip, tcp);
    // printBufferHex((char*)ip, IPHDRLEN + TCPHDRLEN + datalen);   
}

void appendTcpOption(struct iphdr *ip, struct tcphdr *tcp, 
    uint8_t option_kind, uint8_t option_length, char option_data[])

{
    // Find the length of data in the packet - total packet length, 
    // minus IP header and tcp header length through daa offset
    uint8_t data_offset = tcp->doff * 4;
    LOGD("option: data offset (bytes) = %d", data_offset);
    int datalen = ntohs(ip->tot_len) - IPHDRLEN - data_offset;
    LOGD("option: data length (bytes) = %d", datalen);
    // Will add NOP options for alignment
    uint8_t nops = ((option_length / 4) + 1) * 4 - option_length;
    LOGD("option: nops for the option %d = %d (length %d)", option_kind, nops, option_length);
    // This is where the data starts
    char *dataStart = (char*) ip + IPHDRLEN + data_offset;
    // Once the data is moved, the appended option will start here
    char *optionStart = dataStart;
    if (datalen > 0) {    
        // Move all the data by the option length
        memmove(dataStart, dataStart + nops + option_length, datalen);
    }
    // Increase packet length
    LOGD("option: prior total IP length = %d", ntohs(ip->tot_len));
    ip->tot_len = htons(ntohs(ip->tot_len) + nops + option_length);
    LOGD("option: total IP length with the option = %d", ntohs(ip->tot_len));
    tcp->doff = tcp->doff + (nops + option_length) / 4;
    LOGD("option: new data offset %d", tcp->doff);

    for (int n = 0; n < nops; n++) {
        // the NOP option
        *(optionStart + n) = (char) 0x01;  
    }
    *(optionStart + nops) = (char) option_kind;
    if (option_length >= 2) {
        *(optionStart + nops + 1) = (char) option_length;
        if (option_length > 2) {
            memcpy(optionStart + nops + 2, option_data, option_length - 2);
        }
    }

    // Recompute checksum
    tcp->check = 0;
    tcp->check = tcpChecksum(ip, tcp, datalen);
    LOGD("Recomputed TCP checksum %04X", tcp->check);
}

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
test_error handshake(struct sockaddr_in *src, struct sockaddr_in *dst,
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
    
    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote);
    if (!sendPacket(socket, buffer, dst, ntohs(ip->tot_len))) {
        LOGE("TCP handshake ACK failure: %s", strerror(errno));
        return send_error;
    }
    return success;
}

test_error handshake(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint32_t syn_ack, uint16_t syn_urg, uint8_t syn_res,
                uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res)
{
    return handshake(src, dst, socket, ip, tcp, buffer, seq_local, seq_remote,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res, NULL, 0);
}

// Cleanly shutdown the connection with the
// FIN  -> 
//      <- FINACK / FIN
// ACK  ->
//      <- ACK if only FIN previously
test_error shutdownConnection(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote)
{
    test_error ret;
    buildTcpFin(src, dst, ip, tcp, seq_local, seq_remote);
    if (!sendPacket(socket, buffer, dst, ntohs(ip->tot_len)))
        return send_error;

    int len = receivePacket(socket, ip, tcp, dst, src);
    bool finack_received = false;
    if (len > 0) {
        if (tcp->fin && tcp->ack) {
            finack_received = true;
            seq_remote = ntohl(tcp->ack_seq) + 1;
        } else if (!tcp->fin) {
            // Must be a packet with FIN flag set
            return protocol_error;
        }
    } else {
        return receive_error;
    }

    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote);
    if (!sendPacket(socket, buffer, dst, ntohs(ip->tot_len)))
        return send_error;

    if (!finack_received) {
        int len = receivePacket(socket, ip, tcp, dst, src);
        if (len < 0) {
            LOGE("TCP FINACK ACK not received, %d", ret);
        }
        else {
            LOGE("TCP connection closed");
            return success;
        }
    } else {
        return success;
    }
    return success;
}

test_error sendData(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint8_t data_out_res, char *send_payload, int send_length)
{
    memset(buffer, 0, BUFLEN);
    buildTcpData(src, dst, ip, tcp, seq_local, seq_remote, data_out_res, send_payload, send_length);
    if ( sendPacket(socket, buffer, dst, ntohs(ip->tot_len)) )
        return success;
    else
        return send_error;
}

test_error receiveData(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                int &receiveDataLength)
{
    int receiveLength = receivePacket(socket, ip, tcp, dst, src);
    if (receiveLength == -1 || receiveLength < IPHDRLEN + TCPHDRLEN) {
        receiveDataLength = 0;
        return receive_error;
    } 
    receiveDataLength = receiveLength - IPHDRLEN - tcp->doff * 4;
    // TODO: handle the new sequence numbers
    seq_local = ntohl(tcp->ack_seq);
    // When the ACK of a previous packet gets sent separately from the data
    if (receiveDataLength == 0) {
        int receiveLength = receivePacket(socket, ip, tcp, dst, src);
        if (receiveLength == -1 || receiveLength < IPHDRLEN + TCPHDRLEN) {
            receiveDataLength = 0;
            return receive_error;
        }
        receiveDataLength = receiveLength - IPHDRLEN - tcp->doff * 4;
    }
    return success;
}

test_error acknowledgeData(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote, int receiveDataLength)
{
    
    seq_remote = seq_remote + receiveDataLength;
    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote);
    if (!sendPacket(socket, buffer, dst, ntohs(ip->tot_len)))
        return send_error;
}