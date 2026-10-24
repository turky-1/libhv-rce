# libhv `dns_name_decode` — heap overflow to code execution

**A complete, reproducible exploit chain against libhv's DNS parser.**

- **Software:** libhv (ithewei/libhv) — C/C++ event-loop network library
- **File:** `protocol/dns.c`, function `dns_name_decode()`
- **Affected:** libhv 1.3.x, git `060a4b6` (2026-10-20) and every prior release.
  **Unpatched as of this writing.**
- **Class:** CWE-787 (heap out-of-bounds write), CWE-125 (out-of-bounds read)
- **Status:** independently rediscovered and weaponized; the bug was previously
  reported in [issue #851](https://github.com/ithewei/libhv/issues/851)
  (2026-07-21, credited to LL-V) with fix
  [PR #854](https://github.com/ithewei/libhv/pull/854) still open/unmerged.

> This package is an independent technical writeup and exploit. The underlying
> bug was first reported by LL-V; this work adds the full escalation to code
> execution and a runnable PoC. All credit for the initial report goes to LL-V.

---

## The bug

`dns_name_decode()` decodes a DNS wire-format name into a caller buffer with no
destination size and no source length, terminating only on a NUL byte in the
packet:

```c
int dns_name_decode(const char* buf, char* domain) {
    const char* p = buf;
    int len = *p++;               /* signed char: 0xFF -> -1, breaks label math */
    int buflen = 1;
    while (*p != '\0') {          /* stops only at a NUL in the INPUT */
        if (len-- == 0) { len = *p; *domain = '.'; }
        else            { *domain = *p; }
        ++p; ++domain; ++buflen;
    }
    *domain = '\0';
    ++buflen;
    return buflen;
}
```

`dns_unpack()` allocates `dns->answers = malloc(nanswer * sizeof(dns_rr_t))`
(`sizeof(dns_rr_t) == 280`; `name` is `char[256]`) and fills `answers[0].name`
through this decoder. A name longer than 256 bytes writes forward out of
`name[256]`, through the record, and past the allocation into the next heap
chunk. The bytes are attacker-controlled, the length only bounded by the packet.

Reachability: `dns_query()` (public API) does `recvfrom()` → `dns_unpack()` on
an untrusted DNS response. Any libhv application resolving hostnames through
`nslookup()` / `dns_query()` / `dns_unpack()` is reachable by an attacker who
controls the DNS server (or the UDP:53 path).

## The exploit chain

1. **Crash** → 2. **RIP control** → 3. **Code execution**, all verified.

glibc lays two back-to-back `malloc(280)` chunks 0x120 bytes apart. The exploit
relies on that adjacency plus a tcache reuse:

```
A = malloc(280)      # chunk at X
B = malloc(280)      # victim, adjacent at X+0x120; B[0] is a function pointer
free(A)              # A -> tcache
dns_unpack(...)      # answers = malloc(280) reuses A, so answers == A, B at +0x120
long name overflows answers[0].name forward into B[0]
```

Wire-format details that matter:

- A label length byte `>= 0xC0` is read as a DNS compression pointer
  (`if (*(uint8_t*)p >= 192)`), so `0xFF` labels never reach the decoder.
  **`0x3F` (63, the largest valid label length) is used instead.**
- Six `0x3F` labels of 63 bytes each decode to `6*63 + 5 dots = 383` output
  bytes; dots land at offsets 63/127/191/255/319, so offsets **288..295** — the
  bytes that land on `B[0]` — are eight consecutive attacker-chosen bytes.

**Stage 3 — code execution.** `dns_name_decode` cannot emit a NUL byte (it
terminates the copy), so a full x86-64 pointer can't be written. But a non-PIE
code pointer's high five bytes are already `0x00`, so a **3-byte partial
overwrite** of the low bytes redirects `B[0]` from `legit()` to `win()`:

```
[*] win() at 0x401830 (low3 = 30 18 40)
[*] dns_unpack returned 319, B[0] = 0x401830
[*] PWNED: attacker redirected control flow into win()
[BREAD] arbitrary code execution
uid=1000(kali) gid=1000(kali) groups=1000(kali),65534(nogroup)
```

The label stream places `win`'s low three bytes at output offsets 288–290 and a
NUL at 291, stopping the copy right after the partial overwrite.

## Build and run

```bash
./build.sh          # clones libhv, generates hconfig.h, compiles all four PoCs
```

Each PoC:

| file | what it demonstrates |
|---|---|
| `pocs/dns_overflow_poc.c` | ASAN heap-buffer-overflow (write) — the raw bug |
| `pocs/dns_read_poc.c` | ASAN stack-buffer-overflow (read) — no NUL terminator |
| `pocs/dns_hijack_poc.c` | function pointer = `0x4141414141414141`, RIP control |
| `pocs/dns_exec_poc.c` | partial-overwrite redirect → `system()`, code execution |

`dns_exec_poc.c` must be built **without ASAN** (ASAN redzones break the
adjacency); the others are ASAN builds. `build.sh` handles both.

## Fix

Pass bounds into the decoder and validate the wire format: cap each label at 63,
the total name at 255, keep reads inside the packet, advance the packet cursor by
the *wire* length (not the decoded character count), and validate every count
field before use. See PR #854 for the maintainer's own patch.

## Disclosure note

- Original report: [libhv issue #851](https://github.com/ithewei/libhv/issues/851), LL-V, 2026-07-21.
- Fix: [PR #854](https://github.com/ithewei/libhv/pull/854), open/unmerged.
- This package: independent repro + exploit escalation, for documentation and
  responsible disclosure. No live targets were or should be involved.
