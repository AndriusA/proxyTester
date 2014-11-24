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

using namespace std::placeholders;

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
            packetFunctor fn_checkTcpSynAck)
{
    uint16_t packet_length = 0;
    test_error read = receivePacket(sock, ip, tcp, exp_src, exp_dst, packet_length);
    if (read != success) {
        LOGE("SYNACK packet read error %d", read);
        return read;
    }
    if (!tcp->syn || !tcp->ack) {
        LOGE("Not a SYNACK packet");
        return protocol_error;
    }
    if (seq_local != ntohl(tcp->ack_seq)) {
        LOGE("SYNACK packet unexpected ACK number: %u, %u", seq_local, ntohl(tcp->ack_seq));
        return sequence_error;
    }
    
    return fn_checkTcpSynAck(ip, tcp);
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
                packetModifier fn_synExtras,
                packetFunctor fn_checkTcpSynAck)
{
    test_error ret;
    seq_local = 0;
    seq_remote = 0;
    LOGD("Build SYN packet");
    buildTcpSyn(src, dst, ip, tcp);
    LOGD("Add SYN extras");
    fn_synExtras(ip, tcp);
    if (sendPacket(socket, buffer, dst, ntohs(ip->tot_len)) != success) {
        LOGE("TCP SYN packet failure: %s", strerror(errno));
        return syn_error;
    }
    seq_local = ntohl(tcp->seq) + 1;

    // Receive and verify SYNACK
    ret = receiveTcpSynAck(seq_local, socket, ip, tcp, dst, src, fn_checkTcpSynAck);
    if (ret != success) {
        LOGE("TCP SYNACK packet failure: %d, %s", ret, strerror(errno));
        return ret;
    }
    
    uint16_t received_data = htons(ip->tot_len) - IPHDRLEN - tcp->doff * 4;
    seq_remote = ntohl(tcp->seq) + 1 + received_data;
    LOGD("SYNACK \tSeq: %zu \tAck: %zu\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
    
    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote);
    if (sendPacket(socket, buffer, dst, ntohs(ip->tot_len)) != success) {
        LOGE("TCP handshake ACK failure: %s", strerror(errno));
        return ack_error;
    }
    return success;
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