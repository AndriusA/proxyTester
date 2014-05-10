#include <android/log.h>
#include "testsuite.hpp"

#ifndef BUFLEN
#define BUFLEN 4096
#endif

uint32_t SEQ_LOCAL, SEQ_REMOTE, ACKED_REMOTE;

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

uint16_t undo_natting(struct iphdr *ip, struct tcphdr *tcp) {
    uint32_t checksum = ntohs(tcp->check);
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Recalculating packet checksum %d", checksum);
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "... Recalcualting, src ip: %04X%04X, %s", ntohs(ip->saddr & 0xFFFF), ntohs((ip->saddr >> 16) & 0xFFFF), inet_ntoa(*(struct in_addr*) &ip->saddr));
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "... Recalcualting, dst ip: %04X%04X, %s", ntohs(ip->daddr & 0xFFFF), ntohs((ip->daddr >> 16) & 0xFFFF), inet_ntoa(*(struct in_addr*) &ip->daddr));
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "... Recalcualting, src port: %04X, %d", ntohs(tcp->source), ntohs(tcp->source));
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "... Recalcualting, dst port: %04X, %d", ntohs(tcp->dest), ntohs(tcp->dest));
    checksum = csum_add(checksum, ntohs(ip->daddr & 0xFFFF));
    checksum = csum_add(checksum, ntohs((ip->daddr >> 16) & 0xFFFF));
    checksum = csum_add(checksum, ntohs(tcp->dest));
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Recalculated: %d, %04X", checksum, checksum);
    return (uint16_t) checksum;
}

int tcpChecksum(struct iphdr *ip, struct tcphdr *tcp, int datalen) {
    struct pseudohdr * pseudoheader;
    int padding = datalen % 2 ? 1 : 0;
    pseudoheader = (struct pseudohdr *) ( (u_int8_t *) tcp + TCPHDRLEN + datalen + padding );
    
    pseudoheader->src_addr = ip->saddr;
    pseudoheader->dst_addr = ip->daddr;
    pseudoheader->padding = 0;
    pseudoheader->proto = ip->protocol;
    pseudoheader->length = htons(TCPHDRLEN + datalen);

    __android_log_print(ANDROID_LOG_DEBUG, TAG, "data: \t\t");
    printBufferHex((char*) tcp, TCPHDRLEN + datalen + padding + PHDRLEN);

    int checksum = comp_chksum((uint16_t*) tcp,
            TCPHDRLEN + datalen + padding + PHDRLEN);
}

test_error tcpSyn(unsigned long source, unsigned int src_port,
            unsigned long destination, unsigned int dst_port, 
            int sock, char buffer[], struct iphdr *ip, struct tcphdr *tcp) 
{
    int datalen  = 0;

    ip->frag_off    = 0;
    ip->version     = 4;
    ip->ihl         = 5;
    ip->tot_len     = htons(IPHDRLEN + TCPHDRLEN + datalen);
    ip->id          = 0;
    ip->ttl         = 40;
    ip->protocol    = IPPROTO_TCP;
    ip->saddr       = source;
    ip->daddr       = destination;
    ip->check       = 0;

    tcp->source     = htons(src_port);
    tcp->dest       = htons(dst_port);
    tcp->seq        = htonl(random() % 65535);
    tcp->ack_seq    = htonl(0xdeadbeef);
    tcp->doff       = 5;    // Data offset 5 octets (no options)
    tcp->ack        = 0;
    tcp->psh        = 0;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 1;
    tcp->fin        = 0;
    tcp->window     = htons(65535);
    tcp->check      = tcpChecksum(ip, tcp, datalen);

    SEQ_LOCAL = tcp->seq + 1;

    printPacketInfo(ip, tcp);

    struct sockaddr_in to;
    to.sin_addr.s_addr = ip->daddr;
    to.sin_family = AF_INET;
    to.sin_port = tcp->dest;

    int bytes = sendto(sock, buffer, ntohs(ip->tot_len), 0, 
                    (struct sockaddr*) &to, sizeof(to));

    if (bytes == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "sendto() failed: %s", strerror(errno));
        return syn_error;
    }
    return success;
}

test_error tcpReceive(int sock, char buffer[], struct iphdr *ip, struct tcphdr *tcp) {
    int length = recv(sock, buffer, BUFLEN, 0);
    // Set SEQ_REMOTE if receiving a SYNACK packet
    if (tcp->syn) {
        SEQ_REMOTE = tcp->seq + 1;
        ACKED_REMOTE = 0;
    }
    // Or if seeing the expected sequence number
    else if (SEQ_REMOTE == tcp->seq) {
        // Length is the whole packet length
        // Data length is:
        // length - IP header length - TCP header length
        // (tcp data offset in 32 bit/4 byte words)
        SEQ_REMOTE = tcp->seq + (length - IPHDRLEN - tcp->doff * 4);
    }
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Received %d bytes \n", length);
    printPacketInfo(ip, tcp);
    printBufferHex((char*)ip, length);
    return success;
}

test_error tcpSynAck(int sock, char buffer[], struct iphdr *ip, struct tcphdr *tcp) {
    test_error ret = tcpReceive(sock, buffer, ip, tcp);
    if (ret == success)
        undo_natting(ip, tcp);
    return ret;
}

test_error tcpHandshakeAck(unsigned long source, unsigned int src_port,
            unsigned long destination, unsigned int dst_port, 
            int sock, char buffer[], struct iphdr *ip, struct tcphdr *tcp) 
{
    int datalen = 0;
    ip->frag_off = 0;
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(IPHDRLEN + TCPHDRLEN + datalen);
    ip->id = 0;
    ip->ttl = 40;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = source;
    ip->daddr = destination;
    ip->check = 0;

    u_int32_t client_seq = ntohl(tcp->ack_seq);
    SEQ_LOCAL = client_seq;
    SEQ_REMOTE = ntohl(tcp->seq)+1;
    // if (client_seq != SEQ_LOCAL) {
    //     __android_log_print(ANDROID_LOG_WARN, TAG, "Remote returned sequence number does not match our generated! Expected %d, Got %d", SEQ_LOCAL, client_seq);
    //     return 2;
    // }

    tcp->source     = htons(src_port);
    tcp->dest       = htons(dst_port);
    tcp->seq        = htonl(SEQ_LOCAL);
    tcp->ack_seq    = htonl(SEQ_REMOTE);
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
    ACKED_REMOTE = tcp->ack_seq;
    printPacketInfo(ip, tcp);

    struct sockaddr_in to;
    to.sin_addr.s_addr = ip->daddr;
    to.sin_family = AF_INET;
    to.sin_port = tcp->dest;

    int bytes = sendto(sock, buffer, ntohs(ip->tot_len), 0, (struct sockaddr*) &to, sizeof(to));
    if (bytes == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "sendto() failed for ACK: %s", strerror(errno));
        return ack_error;
    }
    return success;
}

test_error tcpSendData(unsigned long source, unsigned int src_port,
            unsigned long destination, unsigned int dst_port, 
            int sock, char buffer[], struct iphdr *ip, struct tcphdr *tcp,
            char data[], int datalen)
{
    u_int32_t client_seq = ntohl(tcp->seq);
    u_int32_t remote_seq = ntohl(tcp->ack_seq);
    memset(buffer, 0, BUFLEN);
    memcpy(buffer + IPHDRLEN + TCPHDRLEN, data, datalen);

    ip->frag_off = 0;
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(IPHDRLEN + TCPHDRLEN + datalen);
    ip->id = 0;
    ip->ttl = 40;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = source;
    ip->daddr = destination;
    ip->check = 0;  

    tcp->source     = htons(src_port);
    tcp->dest       = htons(dst_port);
    tcp->seq        = htonl(client_seq);
    tcp->ack_seq    = htonl(remote_seq);
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
    printBufferHex(data, datalen);

    struct sockaddr_in to;
    to.sin_addr.s_addr = ip->daddr;
    to.sin_family = AF_INET;
    to.sin_port = tcp->dest;

    int bytes = sendto(sock, buffer, ntohs(ip->tot_len), 0, (struct sockaddr*) &to, sizeof(to));
    if (bytes == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "sendto() failed for data packet: %s", strerror(errno));
        return send_error;
    }
    return success;
}

test_error handshake(unsigned long source, unsigned int src_port,
                unsigned long destination, unsigned int dst_port,
                int socket, char buffer[], struct iphdr *ip, struct tcphdr *tcp)
{
    test_error ret;
    ret = tcpSyn(source, src_port, destination, dst_port, socket, buffer, ip, tcp);
    if (ret != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP SYN packet failure: %s", strerror(errno));
        return ret;
    }

    ret = tcpSynAck(socket, buffer, ip, tcp);
    if (ret != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP SYNACK packet failure: %s", strerror(errno));
        return ret;
    } else if (ip->saddr != destination || ip->daddr != source || ntohs(tcp->source) != dst_port || ntohs(tcp->dest) != src_port) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP SYNACK packet failure: wrong packet received");
        return invalid_packet;
    }
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "SYNACK \tSeq: %zu \tAck: %zu\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
    
    ret = tcpHandshakeAck(source, src_port, destination, dst_port, socket, buffer, ip, tcp);
    if (ret != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP handshake ACK failure: %s", strerror(errno));
        return ret;
    }
    return success;
}

test_error runTest(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port) {
    int sock, bytes, on = 1;
    char buffer[BUFLEN] = {0};
    memset(buffer, 0, BUFLEN);
    struct iphdr *ip;
    struct tcphdr *tcp;
    char *data;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1) {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "socket() failed");
        return test_failed;
    }else{
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "socket() ok");
    }

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "setsockopt() failed: %s", strerror(errno));
        return test_failed;
    }else{
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "setsockopt() ok");
    }

    ip = (struct iphdr*) buffer;
    tcp = (struct tcphdr*) (buffer + IPHDRLEN);
    data = buffer + IPHDRLEN + TCPHDRLEN;
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Typecasting ok");

    if (handshake(source, src_port, destination, dst_port, sock, buffer, ip, tcp) != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP handshake failed: %s", strerror(errno));
        return test_failed;
    }

    char sendString[] = "HELLO";
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Sending String \"%s\", of length %d\n", sendString, strlen(sendString));
    tcpSendData(source, src_port, destination, dst_port, sock, buffer, ip, tcp, sendString, strlen(sendString));
    int ret = tcpSynAck(sock, buffer, ip, tcp);

    if (ret != success)
        return test_failed;
    else
        return test_complete;
}