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
    // Undo the simple NATing
    checksum = undo_natting(ip, tcp);
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
//
// param sock       The socket
// param ip         IP header
// param tcp        TCP header
// param exp_src    expected packet source address (IP and port)
// param exp_dst    expected packet destination address (IP and port)
// param length     length of the packet read, passed by reference
// return           success or error code (e.g. timeout or read failure)
test_error receivePacket(int sock, struct iphdr *ip, struct tcphdr *tcp,
    struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst, uint16_t &length)
{
    // will timeout if there is no suitable packet even if there are
    // other packets in the receive buffer
    std::chrono::time_point<std::chrono::system_clock> start, now;
    start = std::chrono::system_clock::now();
    while (true) {
        length = recv(sock, (char*)ip, BUFLEN, 0);
        // Error reading from socket or reading timed out - failure either way
        if (length == -1) {
            return receive_error;
        }

        if (validPacket(ip, tcp, exp_src, exp_dst)) {
            return success;
        }
        else {
            // Read a packet that belongs to some other connection
            // try again unless we have exceeded receive timeout
            now = std::chrono::system_clock::now();
            if (now - start > sock_receive_timeout_sec) {
                LOGD("Packet reading timed out");
                length = -1;
                return receive_timeout;
            }
        }
    }
}

test_error sendPacket(int sock, char buffer[], struct sockaddr_in *dst, uint16_t len) {
    int bytes = sendto(sock, buffer, len, 0, (struct sockaddr*) dst, sizeof(*dst));
    if (bytes == -1) {
        LOGE("sendto() failed for data packet: %s", strerror(errno));
        return send_error;
    }
    return success;
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
            uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res, uint16_t &data_read)
{
    uint16_t packet_length = 0;
    test_error read = receivePacket(sock, ip, tcp, exp_src, exp_dst, packet_length);
    if (read != success) {
        LOGE("SYNACK packet read error %d", read);
        return read;
    }
    if (packet_length >= IPHDRLEN + TCPHDRLEN)
        data_read = packet_length - IPHDRLEN - tcp->doff * 4;
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
                char *synack_payload, uint16_t synack_length)
{
    test_error ret;
    seq_local = 0;
    seq_remote = 0;
    buildTcpSyn(src, dst, ip, tcp, syn_ack, syn_urg, syn_res);
    if (sendPacket(socket, buffer, dst, ntohs(ip->tot_len)) != success) {
        LOGE("TCP SYN packet failure: %s", strerror(errno));
        return syn_error;
    }
    seq_local = ntohl(tcp->seq) + 1;

    // Receive and verify that incoming packet source is our destination and vice-versa
    uint16_t data_read = 0;
    ret = receiveTcpSynAck(seq_local, socket, ip, tcp, dst, src, synack_urg, synack_check, synack_res, data_read);
    if (ret != success) {
        LOGE("TCP SYNACK packet failure: %d, %s", ret, strerror(errno));
        return ret;
    }
    char *data = buffer + IPHDRLEN + tcp->doff * 4;
    uint16_t datalen = 0;
    if (synack_length > 0) {
        if (data_read != synack_length) {
            LOGD("SYNACK data_read different than expected");
            return synack_error_data_length;
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
    if (sendPacket(socket, buffer, dst, ntohs(ip->tot_len)) != success) {
        LOGE("TCP handshake ACK failure: %s", strerror(errno));
        return ack_error;
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
    if (sendPacket(socket, buffer, dst, ntohs(ip->tot_len)) != success)
        return send_error;

    uint16_t len;
    test_error readStatus;
    readStatus = receivePacket(socket, ip, tcp, dst, src, len);
    bool finack_received = false;
    if (readStatus == success) {
        if (tcp->fin && tcp->ack) {
            finack_received = true;
            seq_remote = ntohl(tcp->ack_seq) + 1;
        } else if (!tcp->fin) {
            // Must be a packet with FIN flag set
            return protocol_error;
        }
    } else {
        return readStatus;
    }

    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote);
    if (sendPacket(socket, buffer, dst, ntohs(ip->tot_len)) != success)
        return send_error;

    if (!finack_received) {
        readStatus = receivePacket(socket, ip, tcp, dst, src, len);
        if (readStatus == success)
            LOGE("TCP connection closed");
        else
            LOGE("TCP FINACK ACK not received, %d", ret);
    }
    return success;
}

test_error sendData(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint8_t data_out_res, char *send_payload, uint16_t send_length)
{
    memset(buffer, 0, BUFLEN);
    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote, data_out_res);
    appendData(ip, tcp, send_payload, send_length);
    return sendPacket(socket, buffer, dst, ntohs(ip->tot_len));
}

test_error receiveData(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint16_t &receiveDataLength)
{
    uint16_t receiveLength;
    test_error receive;
    receive = receivePacket(socket, ip, tcp, dst, src, receiveLength);
    if (receive != success)
        return receive;
    else if (receiveLength < IPHDRLEN + TCPHDRLEN) {
        receiveDataLength = 0;
        return receive_error_data;
    } 
    receiveDataLength = receiveLength - IPHDRLEN - tcp->doff * 4;
    // TODO: handle the new sequence numbers
    seq_local = ntohl(tcp->ack_seq);
    // When the ACK of a previous packet gets sent separately from the data
    if (receiveDataLength == 0) {
        receive = receivePacket(socket, ip, tcp, dst, src, receiveLength);
        if (receive != success)
            return receive;
        else if (receiveLength == -1 || receiveLength < IPHDRLEN + TCPHDRLEN) {
            receiveDataLength = 0;
            return receive_error_data;
        }
        receiveDataLength = receiveLength - IPHDRLEN - tcp->doff * 4;
    }
    return success;
}

test_error acknowledgeData(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote, uint16_t receiveDataLength)
{
    
    seq_remote = seq_remote + receiveDataLength;
    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote);
    if (sendPacket(socket, buffer, dst, ntohs(ip->tot_len)) != success)
        return send_error;
}