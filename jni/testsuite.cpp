#include <android/log.h>
#include "testsuite.hpp"
#include "util.hpp"

#ifndef BUFLEN
#define BUFLEN 4096
#endif

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

int tcpChecksum(struct iphdr *ip, struct tcphdr *tcp, int datalen) {
    // Add pseudoheader at the end of the packet for simplicity,
    struct pseudohdr * pseudoheader;
    // Need to add padding between data and pseudoheader
    // if data payload length is not a multiple of 2,
    // checksum is a 2 byte value.
    int padding = datalen % 2 ? 1 : 0;
    pseudoheader = (struct pseudohdr *) ( (u_int8_t *) tcp + TCPHDRLEN + datalen + padding );
    pseudoheader->src_addr = ip->saddr;
    pseudoheader->dst_addr = ip->daddr;
    pseudoheader->padding = 0;
    pseudoheader->proto = ip->protocol;
    pseudoheader->length = htons(TCPHDRLEN + datalen);
    // compute chekcsum from the bound of the tcp header to the appended pseudoheader
    int checksum = comp_chksum((uint16_t*) tcp,
            TCPHDRLEN + datalen + padding + PHDRLEN);
    return checksum;
}

uint16_t undo_natting(struct iphdr *ip, struct tcphdr *tcp) {
    uint32_t checksum = ntohs(tcp->check);
    // Add back destination (own!) IP address and port number to undo what NAT modifies
    checksum = csum_add(checksum, ntohs(ip->daddr & 0xFFFF));
    checksum = csum_add(checksum, ntohs((ip->daddr >> 16) & 0xFFFF));
    checksum = csum_add(checksum, ntohs(tcp->dest));
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Checksum NATing recalculated: %d, %04X", checksum, checksum);
    return (uint16_t) checksum;
}

test_error validPacket(struct iphdr *ip, struct tcphdr *tcp,
    struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst)
{
    if ( ip->saddr != exp_src->sin_addr.s_addr || ip->daddr != exp_dst->sin_addr.s_addr ) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Corrupted packet received: unexpected IP address");
        return invalid_packet;
    } else if ( tcp->source != exp_src->sin_port || tcp->dest != exp_dst->sin_port ) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Corrupted packet received: unexpected port number");
        return invalid_packet;
    } else {
        return success;
    }
}

test_error receivePacket(int sock, struct iphdr *ip, struct tcphdr *tcp,
    struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst)
{
    int length = recv(sock, (char*)ip, BUFLEN, 0);
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Received %d bytes \n", length);
    printPacketInfo(ip, tcp);
    printBufferHex((char*)ip, length);
    return validPacket(ip, tcp, exp_src, exp_dst);
}

test_error sendPacket(int sock, char buffer[], struct sockaddr_in *dst, uint16_t len) {
    int bytes = sendto(sock, buffer, len, 0, (struct sockaddr*) dst, sizeof(*dst));
    if (bytes == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "sendto() failed for data packet: %s", strerror(errno));
        return send_error;
    }
    return success;
}

test_error receiveTcpSynAck(uint32_t seq_local, int sock, struct iphdr *ip, struct tcphdr *tcp,
    struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst)
{
    test_error ret = receivePacket(sock, ip, tcp, exp_src, exp_dst);
    if (ret != success) 
        return ret;
    if (seq_local != ntohl(tcp->ack_seq)) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "SYNACK packet unexpected ACK number: %d, %d", seq_local, ntohl(tcp->ack_seq));
        return sequence_error;
    }
    undo_natting(ip, tcp);
    return success;
}

test_error buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp) 
{
    // IP packet with TCP and no payload
    int datalen = 0;
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);

    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(random() % 65535);
    // tcp->ack_seq    = htonl(0xdeadbeef);
    tcp->doff       = 5;    // Data offset 5 octets (no options)
    tcp->ack        = 0;
    tcp->psh        = 0;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 1;
    tcp->fin        = 0;
    tcp->window     = htons(65535);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
    printPacketInfo(ip, tcp);
}

test_error buildTcpHandshakeAck(struct sockaddr_in *src, struct sockaddr_in *dst,
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
    tcp->window     = htons(65535);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
    printPacketInfo(ip, tcp);
}

test_error buildTcpFin(struct sockaddr_in *src, struct sockaddr_in *dst,
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
    tcp->ack        = 0;
    tcp->psh        = 0;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 0;
    tcp->fin        = 1;
    tcp->window     = htons(65535);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
    printPacketInfo(ip, tcp);
}

test_error buildTcpData(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t seq_local, uint32_t seq_remote,
            char data[], int datalen)
{
    memset(ip, 9, BUFLEN);
    // (u_int8_t *) tcp + TCPHDRLEN + datalen + padding
    char *dataStart = (char*)ip + IPHDRLEN + TCPHDRLEN;
    memcpy(dataStart, data, datalen);
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);

    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(seq_local);
    tcp->ack_seq    = htonl(seq_remote);
    tcp->doff       = 5;
    tcp->ack        = 1;
    tcp->psh        = 1;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 0;
    tcp->fin        = 0;
    tcp->window     = htons(65535);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);

    printPacketInfo(ip, tcp);
    printBufferHex((char*)ip, IPHDRLEN + TCPHDRLEN + datalen);   
}

test_error handshake(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote)
{
    test_error ret;
    seq_local = 0;
    seq_remote = 0;
    buildTcpSyn(src, dst, ip, tcp);
    seq_local = ntohl(tcp->seq) + 1;
    ret = sendPacket(socket, buffer, dst, ntohs(ip->tot_len));
    if (ret != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP SYN packet failure: %s", strerror(errno));
        return ret;
    }

    // Receive and verify that incoming packet source is our destination and vice-versa
    ret = receiveTcpSynAck(seq_local, socket, ip, tcp, dst, src);
    seq_remote = ntohl(tcp->seq) + 1;
    if (ret != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP SYNACK packet failure: %d, %s", ret, strerror(errno));
        return ret;
    }
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "SYNACK \tSeq: %zu \tAck: %zu\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
    
    buildTcpHandshakeAck(src, dst, ip, tcp, seq_local, seq_remote);
    ret = sendPacket(socket, buffer, dst, ntohs(ip->tot_len));
    if (ret != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP handshake ACK failure: %s", strerror(errno));
        return ret;
    }
    return success;
}

test_error shutdownConnection(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote)
{
    test_error ret;
    buildTcpFin(src, dst, ip, tcp, seq_local, seq_remote);
    ret = sendPacket(socket, buffer, dst, ntohs(ip->tot_len));
    if (ret != success)
        return ret;

    ret = receivePacket(socket, ip, tcp, dst, src);
    bool finack_received = false;
    if (ret == success) {
        if (tcp->fin && tcp->ack) {
            finack_received = true;
            seq_remote = ntohl(tcp->ack_seq) + 1;
        }
    } else {
        return ret;
    }

    buildTcpData(src, dst, ip, tcp, seq_local, seq_remote, NULL, 0);
    ret = sendPacket(socket, buffer, dst, ntohs(ip->tot_len));
    if (ret != success)
        return ret;

    if (!finack_received) {
        ret = receivePacket(socket, ip, tcp, dst, src);
        if (ret != success) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP FINACK ACK not received, %d", ret);
        }
        else {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP connection closed");
            return success;
        }
    } else {
        return success;
    }


}

test_error setupSocket(int &sock) {
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1) {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "socket() failed");
        return test_failed;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "socket() ok");
    }

    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "setsockopt() failed: %s", strerror(errno));
        return test_failed;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "setsockopt() ok");
    }

    struct timeval tv;
    tv.tv_sec = 30;  /* 30 Secs Timeout */
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors
    if ( setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) == -1 ) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "setsockopt receive timeout failed: %s", strerror(errno));
    }

    return success;
}

test_error runTest(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port) {
    int sock;
    char buffer[BUFLEN] = {0};
    struct iphdr *ip;
    struct tcphdr *tcp;

    if (setupSocket(sock) != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Socket setup failed: %s", strerror(errno));
        return test_failed;
    }

    ip = (struct iphdr*) buffer;
    tcp = (struct tcphdr*) (buffer + IPHDRLEN);
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Typecasting ok");

    struct sockaddr_in src, dst;
    src.sin_family = AF_INET;
    src.sin_port = htons(src_port);
    src.sin_addr.s_addr = htonl(source);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = htonl(destination);
    uint32_t seq_local, seq_remote;

    if (handshake(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote) != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP handshake failed: %s", strerror(errno));
        return test_failed;
    }

    char sendString[] = "HELLO";
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Sending String \"%s\", of length %d\n", sendString, strlen(sendString));
    buildTcpData(&src, &dst, ip, tcp, seq_local, seq_remote, sendString, strlen(sendString));
    test_error ret = sendPacket(sock, buffer, &dst, ntohs(ip->tot_len));
    if (ret == success) {
        ret = receivePacket(sock, ip, tcp, &dst, &src);
        // TODO: handle the new sequence numbers
        seq_local = ntohl(tcp->ack_seq);
    }

    shutdownConnection(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote);

    if (ret != success)
        return test_failed;
    else
        return test_complete;
}

