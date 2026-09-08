---
layout: post
title: "PartialEncryption"
date: 2026-09-08
categories: [Reverse Engineering]
difficulty: Easy
platform: HackTheBox
tags: []
excerpt: "Reversing a Windows PE that decrypts small runtime code chunks with AES-NI before validating the flag byte by byte."
---

## Analysis

In this Reverse Engineering challenge, we are given a Windows executable:

```bash
$ file partialencryption.exe
partialencryption.exe: PE32+ executable (console) x86-64, for MS Windows, 5 sections
```

Running it without arguments shows the expected usage:

```bash
$ wine partialencryption.exe
./chal <flag>
```

Testing a short input gives a different failure message:

```bash
$ wine partialencryption.exe test
Nope
```

And a wrong input with the expected shape gives:

```bash
$ wine partialencryption.exe 'HTB{AAAAAAAAAAAAAAAAA}'
No
```

The binary does not expose the flag through normal strings:

```bash
$ strings -n 4 partialencryption.exe
VirtualAlloc
VirtualProtect
VirtualFree
IsDebuggerPresent
putchar
...
```

The interesting imports are `VirtualAlloc`, `VirtualProtect`, and `VirtualFree`. This usually means the program is building or decrypting code at runtime, marking it executable, and then calling it.

Opening the binary in radare2, `main` is small and calls several custom functions:

```asm
0x1400015c1      call fcn.140001130
0x1400015e8      call fcn.1400012b0
0x14000160f      call fcn.1400013b0
0x140001636      call fcn.1400011f0
```

Each function receives pointers to `putchar`, `exit`, `argc`, `argv`, and a small status variable. This hinted that the real logic is hidden inside decrypted code chunks.

## Decryption

The helper at `0x140001050` decrypts chunks from `.data`.

The high-level logic is:

```text
VirtualAlloc(size)
for each 16-byte block:
    build a 16-byte key where every byte is the block index
    decrypt the encrypted block using AES-NI instructions
    write the plaintext block into the allocated buffer
VirtualProtect(buffer, size, PAGE_EXECUTE_READ)
return buffer
```

The core AES-NI transform is in `fcn.140001000`:

```asm
movdqu          xmm0, [rdx]
aeskeygenassist xmm0, xmm0, 0
movdqu          xmm1, [rdx]
aeskeygenassist xmm1, xmm1, 0x10
movdqu          xmm2, [rcx]
pxor            xmm2, xmm1
aesdeclast      xmm1, xmm0
movdqa          xmm0, xmm1
ret
```

Instead of trying to manually execute all of the runtime code, I dumped the encrypted chunks from `.data` and used the same AES-NI operations to recover the plaintext code.

The important chunk addresses were visible from the calls to the decryptor:

```asm
0x140004000, size 0x70
0x140004070, size 0x40
0x1400040b0, size 0x30
0x1400040e0, size 0x30
0x140004110, size 0x30
0x140004140, size 0x1a0
0x1400042e0, size 0x1e0
0x1400044c0, size 0x270
0x140004730, size 0x100
```

I used a small C helper to apply the same AES-NI transform:

```c
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>

static __m128i transform(const uint8_t *cipher, uint8_t idx) {
    uint8_t key[16];
    memset(key, idx, sizeof(key));

    __m128i k = _mm_loadu_si128((const __m128i *)key);
    __m128i r0 = _mm_aeskeygenassist_si128(k, 0x00);
    __m128i r1 = _mm_aeskeygenassist_si128(k, 0x10);
    __m128i x = _mm_loadu_si128((const __m128i *)cipher);

    x = _mm_xor_si128(x, r1);
    x = _mm_aesdeclast_si128(x, r0);
    return x;
}
```

Compiled with AES support:

```bash
$ gcc -O2 -maes -msse4.1 dump_partial.c -o dump_partial
$ ./dump_partial partialencryption.exe
/tmp/chunk_140004000.bin
/tmp/chunk_140004070.bin
/tmp/chunk_1400040b0.bin
/tmp/chunk_1400040e0.bin
/tmp/chunk_140004110.bin
/tmp/chunk_140004140.bin
/tmp/chunk_1400042e0.bin
/tmp/chunk_1400044c0.bin
/tmp/chunk_140004730.bin
```

Disassembling the first decrypted chunk showed that it prints the usage string one character at a time:

```asm
mov cl, 0x2e
call [rsp+0x30]
mov cl, 0x2f
call [rsp+0x30]
mov cl, 0x63
call [rsp+0x30]
mov cl, 0x68
call [rsp+0x30]
...
```

Those bytes spell:

```text
./chal <flag>
```

So the decrypted chunks are valid executable code, and some of them contain the validation logic.

## Extraction

The validator chunks compare `argv[1]` against hardcoded bytes. A typical comparison looks like this:

```asm
movsx eax, byte [rax+rcx]
cmp eax, 0x48
jz valid
mov dword [rsp], 1
```

Here `0x48` is ASCII `H`.

To avoid manually reading every comparison, I used Capstone to extract the index and expected byte from each decrypted chunk:

```python
from capstone import *
from capstone.x86 import *
from pathlib import Path

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

for f in sorted(Path("/tmp").glob("chunk_*.bin")):
    code = f.read_bytes()
    checks = []
    last_index = None

    for insn in md.disasm(code, 0):
        if insn.mnemonic == "imul" and len(insn.operands) == 3:
            ops = insn.operands
            if ops[0].type == X86_OP_REG and insn.reg_name(ops[0].reg) == "rcx":
                if ops[2].type == X86_OP_IMM:
                    last_index = ops[2].imm & 0xff

        if insn.mnemonic == "cmp" and last_index is not None:
            ops = insn.operands
            if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
                checks.append((last_index, ops[1].imm & 0xff))
                last_index = None

    if checks:
        print(f.name, checks, "".join(chr(c) for _, c in checks))
```

The extracted comparisons were:

```text
chunk_140004140.bin [(0, 72), (1, 84), (2, 66), (3, 123), (21, 125)] HTB{}
chunk_1400042e0.bin [(4, 87), (5, 51), (6, 105), (7, 82), (8, 100), (9, 95)] W3iRd_
chunk_1400044c0.bin [(10, 82), (11, 85), (12, 110), (13, 84), (14, 49), (15, 109), (16, 51), (17, 95)] RUnT1m3_
chunk_140004730.bin [(18, 68), (19, 69), (20, 67)] DEC
```

Putting the bytes back at their original indexes gives:

```python
flag = list("?" * 22)

checks = [
    (0, 72), (1, 84), (2, 66), (3, 123), (21, 125),
    (4, 87), (5, 51), (6, 105), (7, 82), (8, 100), (9, 95),
    (10, 82), (11, 85), (12, 110), (13, 84), (14, 49),
    (15, 109), (16, 51), (17, 95),
    (18, 68), (19, 69), (20, 67),
]

for i, c in checks:
    flag[i] = chr(c)

print("".join(flag))
```

Output:

```text
HTB{W3iRd_RUnT1m3_DEC}
```

Finally, I validated the recovered flag with Wine:

```bash
$ wine partialencryption.exe 'HTB{W3iRd_RUnT1m3_DEC}'
Yes
```

## Flag

`HTB{W3iRd_RUnT1m3_DEC}`
