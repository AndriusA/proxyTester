#include <sys/types.h>
#include <stdlib.h>

void printPacketInfo(struct iphdr *ip, struct tcphdr *tcp);
void printBufferHex(char *buffer, int length);
uint16_t comp_chksum(uint16_t *addr, int len);