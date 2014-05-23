#include <android/log.h>
#include "testsuite.hpp"
#include "util.hpp"

#ifndef BUFLEN
#define BUFLEN 65535
#endif

#define TCPWINDOW (BUFLEN - IPHDRLEN - TCPHDRLEN)

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
        // __android_log_print(ANDROID_LOG_ERROR, TAG, "Corrupted packet received: unexpected IP address");
        return invalid_packet;
    } else if ( tcp->source != exp_src->sin_port || tcp->dest != exp_dst->sin_port ) {
        // __android_log_print(ANDROID_LOG_ERROR, TAG, "Corrupted packet received: unexpected port number");
        return invalid_packet;
    } else {
        return success;
    }
}

int receivePacket(int sock, struct iphdr *ip, struct tcphdr *tcp,
    struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst)
{
    while (true) {
        int length = recv(sock, (char*)ip, BUFLEN, 0);
        // __android_log_print(ANDROID_LOG_DEBUG, TAG, "Received %d bytes \n", length);
        if (length == -1) {
            // if (errno == EAGAIN || errno == EWOULDBLOCK)
            //     return receive_timeout;
            // else
            //     return receive_error;
            return length;
        }

        if (validPacket(ip, tcp, exp_src, exp_dst) == success) {
            printPacketInfo(ip, tcp);
            printBufferHex((char*)ip, length);
            return length;
        }
        else {
            // __android_log_print(ANDROID_LOG_DEBUG, TAG, "Packet does not match connection, continue waiting");
        }
    }
    // return success;
}

test_error sendPacket(int sock, char buffer[], struct sockaddr_in *dst, uint16_t len) {
    int bytes = sendto(sock, buffer, len, 0, (struct sockaddr*) dst, sizeof(*dst));
    if (bytes == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "sendto() failed for data packet: %s", strerror(errno));
        return send_error;
    }
    return success;
}

test_error receiveTcpSynAck(uint32_t seq_local, int sock, 
            struct iphdr *ip, struct tcphdr *tcp,
            struct sockaddr_in *exp_src, struct sockaddr_in *exp_dst,
            uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res)
{
    int packet_length = receivePacket(sock, ip, tcp, exp_src, exp_dst);
    if (packet_length < 0) 
        return receive_error;
    if (!tcp->syn || !tcp->ack) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Not a SYNACK packet");
        return protocol_error;
    }
    if (seq_local != ntohl(tcp->ack_seq)) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "SYNACK packet unexpected ACK number: %d, %d", seq_local, ntohl(tcp->ack_seq));
        return sequence_error;
    }
    if (synack_urg != 0 && ntohs(tcp->urg_ptr) != synack_urg) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "SYNACK packet expected urg %04X, got: %04X", synack_urg, ntohs(tcp->urg_ptr));
        return synack_error_urg;
    }
    if (synack_check != 0) {
        uint16_t check = undo_natting(ip, tcp);
        if (synack_check != check) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "SYNACK packet expected check %04X, got: %04X", synack_check, check);
            return synack_error_urg;
        }
    }
    if (synack_res != 0 && synack_res != (tcp->res1 & 0xF) ) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "SYNACK packet expected res %02X, got: %02X", synack_res, (tcp->res1 & 0xF));
        return synack_error_urg;
    }
    
    return success;
}

test_error buildTcpSyn(struct sockaddr_in *src, struct sockaddr_in *dst,
            struct iphdr *ip, struct tcphdr *tcp,
            uint32_t syn_ack, uint32_t syn_urg, uint8_t syn_res) 
{
    // IP packet with TCP and no payload
    int datalen = 0;
    buildIPHeader(ip, src->sin_addr.s_addr, dst->sin_addr.s_addr, datalen);

    tcp->source     = src->sin_port;
    tcp->dest       = dst->sin_port;
    tcp->seq        = htonl(random() % 65535);
    tcp->ack_seq    = htonl(syn_ack);
    tcp->res1       = syn_res & 0xF;           // 4 bits reserved field
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
    printPacketInfo(ip, tcp);
}

test_error buildTcpAck(struct sockaddr_in *src, struct sockaddr_in *dst,
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
    tcp->ack        = 1;
    tcp->psh        = 0;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 0;
    tcp->fin        = 1;
    tcp->window     = htons(TCPWINDOW);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);
    printPacketInfo(ip, tcp);
}

test_error buildTcpData(struct sockaddr_in *src, struct sockaddr_in *dst,
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
    tcp->psh        = 1;
    tcp->rst        = 0;
    tcp->urg        = 0;
    tcp->syn        = 0;
    tcp->fin        = 0;
    tcp->window     = htons(TCPWINDOW);
    tcp->check      = 0;
    tcp->check      = tcpChecksum(ip, tcp, datalen);

    printPacketInfo(ip, tcp);
    printBufferHex((char*)ip, IPHDRLEN + TCPHDRLEN + datalen);   
}

test_error handshake(struct sockaddr_in *src, struct sockaddr_in *dst,
                int socket, struct iphdr *ip, struct tcphdr *tcp, char buffer[],
                uint32_t &seq_local, uint32_t &seq_remote,
                uint32_t syn_ack, uint16_t syn_urg, uint8_t syn_res,
                uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res)
{
    test_error ret;
    seq_local = 0;
    seq_remote = 0;
    buildTcpSyn(src, dst, ip, tcp, syn_ack, syn_urg, syn_res);
    seq_local = ntohl(tcp->seq) + 1;
    ret = sendPacket(socket, buffer, dst, ntohs(ip->tot_len));
    if (ret != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP SYN packet failure: %s", strerror(errno));
        return ret;
    }

    // Receive and verify that incoming packet source is our destination and vice-versa
    ret = receiveTcpSynAck(seq_local, socket, ip, tcp, dst, src, synack_urg, synack_check, synack_res);
    seq_remote = ntohl(tcp->seq) + 1;
    if (ret != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP SYNACK packet failure: %d, %s", ret, strerror(errno));
        return ret;
    }
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "SYNACK \tSeq: %zu \tAck: %zu\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
    
    buildTcpAck(src, dst, ip, tcp, seq_local, seq_remote);
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

    buildTcpData(src, dst, ip, tcp, seq_local, seq_remote, 0, NULL, 0);
    ret = sendPacket(socket, buffer, dst, ntohs(ip->tot_len));
    if (ret != success)
        return ret;

    if (!finack_received) {
        int len = receivePacket(socket, ip, tcp, dst, src);
        if (len < 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP FINACK ACK not received, %d", ret);
        }
        else {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP connection closed");
            return success;
        }
    } else {
        return success;
    }
    return success;
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
    tv.tv_sec = 10;  /* 10 Secs Timeout */
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors
    if ( setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) == -1 ) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "setsockopt receive timeout failed: %s", strerror(errno));
    }

    return success;
}

test_error runTest(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port,
            uint32_t syn_ack, uint16_t syn_urg, uint8_t syn_res,
            uint16_t synack_urg, uint16_t synack_check, uint8_t synack_res,
            uint8_t data_out_res, uint8_t data_in_res,
            char *send_payload, int send_length, char *expect_payload, int expect_length)
{
    int sock;
    char buffer[BUFLEN] = {0};
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct sockaddr_in src, dst;
    uint32_t seq_local, seq_remote;
    ip = (struct iphdr*) buffer;
    tcp = (struct tcphdr*) (buffer + IPHDRLEN);
    char *data = buffer + IPHDRLEN + TCPHDRLEN;

    if (setupSocket(sock) != success) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Socket setup failed: %s", strerror(errno));
        return test_failed;
    }

    src.sin_family = AF_INET;
    src.sin_port = htons(src_port);
    src.sin_addr.s_addr = htonl(source);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = htonl(destination);

    if (handshake(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote, 
        syn_ack, syn_urg, syn_res, 
        synack_urg, synack_check, synack_res) != success)
    {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP handshake failed: %s", strerror(errno));
        return test_failed;
    }

    memset(buffer, 0, BUFLEN);
    buildTcpData(&src, &dst, ip, tcp, seq_local, seq_remote, data_out_res, send_payload, send_length);
    test_error ret = sendPacket(sock, buffer, &dst, ntohs(ip->tot_len));
    if (ret == success) {
        int receiveLength = receivePacket(sock, ip, tcp, &dst, &src);

        if (memcmp(data, expect_payload, expect_length) != 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Payload wrong value, expected for iplen %d, tcplen %d:", IPHDRLEN, TCPHDRLEN);
            printBufferHex(data, expect_length);
            printBufferHex(expect_payload, expect_length);
            ret = test_failed;
        }

        if (tcp->res1 != (data_in_res & 0xF)) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Data packet reserved field wrong value: %02X, expected %02X", tcp->res1, data_in_res & 0xF);
            ret = test_failed;
        }

        int dataLength = receiveLength - IPHDRLEN - TCPHDRLEN;
        // TODO: handle the new sequence numbers
        seq_local = ntohl(tcp->ack_seq);
        if (dataLength > 0) {
            seq_remote = seq_remote + dataLength;
            buildTcpAck(&src, &dst, ip, tcp, seq_local, seq_remote);
            sendPacket(sock, buffer, &dst, ntohs(ip->tot_len));
            // if (ret != success) {
            //     __android_log_print(ANDROID_LOG_ERROR, TAG, "TCP Data ACK failure: %s", strerror(errno));
            // }
        }
    }

    shutdownConnection(&src, &dst, sock, ip, tcp, buffer, seq_local, seq_remote);

    if (ret != success)
        return test_failed;
    else
        return test_complete;
}

test_error runTest_ack_only(uint32_t source, uint16_t src_port, uint32_t destination, uint16_t dst_port) {
    uint32_t syn_ack = 0xbeef0001;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    int expect_length = 4;
    char expect_payload[expect_length];
    expect_payload[0] = (syn_ack >> 8*3) & 0xFF;
    expect_payload[1] = (syn_ack >> 8*2) & 0xFF;
    expect_payload[2] = (syn_ack >> 8*1) & 0xFF;
    expect_payload[3] = syn_ack & 0xFF;
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}

test_error runTest_urg_only(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe02;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    int expect_length = 2;
    char expect_payload[expect_length];
    expect_payload[0] = (syn_urg >> 8) & 0xFF;
    expect_payload[1] = syn_urg & 0xFF;
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}
test_error runTest_ack_urg(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0003;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0xbe03;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}
test_error runTest_plain_urg(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0xbe04;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}
test_error runTest_ack_checksum_incorrect(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0005;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}
test_error runTest_ack_checksum(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0xbeef0006;
    uint16_t syn_urg = 0;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}
test_error runTest_urg_urg(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe07;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0xbe07;
    uint16_t synack_check = 0;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}
test_error runTest_urg_checksum(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe08;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}
test_error runTest_urg_checksum_incorrect(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0xbe09;
    uint8_t syn_res = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0xbeef;
    uint8_t synack_res = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    return runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
}
test_error runTest_reserved_syn(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t data_out_res = 0;
    uint8_t data_in_res = 0;

    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);
    
    uint8_t syn_res = 0b0001;
    uint8_t synack_res = 0b0001;
    test_error res1 = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res1 == test_complete)
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Reserved byte 0b0001 passed");

    syn_res = 0b0010;
    synack_res = 0b0010;
    test_error res2 = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res2 == test_complete)
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Reserved byte 0b0010 passed");

    syn_res = 0b0100;
    synack_res = 0b0100;
    test_error res3 = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res3 == test_complete)
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Reserved byte 0b0100 passed");

    syn_res = 0b1000;
    synack_res = 0b1000;
    test_error res4 = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res1 == test_complete)
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Reserved byte 0b1000 passed");

    if (res1 == test_complete && res2 == test_complete && res3 == test_complete && res4 == test_complete) {
        return test_complete;
    } else {
        return test_failed;
    }
}
test_error runTest_reserved_est(u_int32_t source, u_int16_t src_port, u_int32_t destination, u_int16_t dst_port)
{
    uint32_t syn_ack = 0;
    uint16_t syn_urg = 0;
    uint16_t synack_urg = 0;
    uint16_t synack_check = 0;
    uint8_t syn_res = 0;
    uint8_t synack_res = 0;
    
    char send_payload[] = "HELLO";
    int send_length = strlen(send_payload);
    char expect_payload[] = "OLLEH";
    int expect_length = strlen(expect_payload);

    uint8_t data_out_res = 0b0001;
    uint8_t data_in_res = 0b0001;
    test_error res1 = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res1 == test_complete)
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Reserved byte 0b0001 passed");

    data_out_res = 0b0010;
    data_in_res = 0b0010;
    test_error res2 = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res2 == test_complete)
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Reserved byte 0b0010 passed");

    data_out_res = 0b0100;
    data_in_res = 0b0100;
    test_error res3 = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res3 == test_complete)
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Reserved byte 0b0100 passed");

    data_out_res = 0b1000;
    data_in_res = 0b1000;
    test_error res4 = runTest(source, src_port, destination, dst_port,
        syn_ack, syn_urg, syn_res, synack_urg, synack_check, synack_res,
        data_out_res, data_in_res,
        send_payload, send_length, expect_payload, expect_length);
    if (res1 == test_complete)
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Reserved byte 0b1000 passed");

    if (res1 == test_complete && res2 == test_complete && res3 == test_complete && res4 == test_complete) {
        return test_complete;
    } else {
        return test_failed;
    }

    return test_not_implemented;
}
