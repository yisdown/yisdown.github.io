---
layout: post
title: "Atypical Heap"
date: 2026-06-04
categories: [Pwn]
difficulty: Medium
platform: UNbreakable Romania 2026
tags: [pwn, heap, musl, libc, allocator]
excerpt: "Bypassing musl allocator security by corrupting internal heap structures to redirect execution flow to system()."
---

## Summary

The challenge provides a note manager binary compiled with musl libc. It features two critical vulnerabilities:

* Out-of-Bounds (OOB) Read: Allows leaking heap and allocator metadata.
* Arbitrary 8-byte Write: Provides a primitive to write controlled data anywhere in memory (aligned to 8 bytes).

The exploit leverages the OOB read to bypass PIE/ASLR, corrupts musl allocator metadata to gain an arbitrary memory write, and ultimately hijacks the atexit() linked list to redirect execution flow to system().

## Analysis

### Recon

Unlike glibc (which uses complex bins), musl uses a design based on "groups" and "slots." Its metadata is often stored inline, meaning an OOB read can easily cross into critical allocator structures.

### Vulnerability 1: Arbitrary Write

The hidden menu option accepts:

* Address
* Value

and writes directly to memory:

```c
*ptr = value;
```

No bounds checks are performed.

---

### Vulnerability 2: OOB Read

The application fails to validate the requested read size against the allocated chunk size:

```c
sz <= MAX_NOTE_SIZE
```

By reading 0x100 bytes from a 0x20 byte chunk, we leak adjacent heap headers and pointers, essential for calculating the base addresses of the binary and the musl library.

## Exploitation

### Step A: Information Leak
Heap Layout: Create multiple chunks to stabilize the heap.

Leak: Trigger an OOB read on a chunk to retrieve a pointer pointing back to the allocator's internal structures.

Calculate Base: Subtract the known static offset from the leaked pointer to find the musl base address.

### Step B: Allocator Hijacking
Using the arbitrary write primitive, we target the allocator’s internal "group" structures. By overwriting a pointer to point to a controlled address, we trick the allocator into returning a new chunk at a location of our choosing (e.g., inside the atexit list).

### Step C: Hijacking atexit()
In musl, functions registered via atexit() are stored in a linked list.

Overwrite: Use the arbitrary write to replace a function pointer in the atexit list with the address of system().

Command Injection: Write a command string (e.g., cat flag.txt) into a writable section of the heap or data segment.

Trigger: Call the program’s exit function. The atexit handler executes our injected system() call with our chosen command string as the argument.

## Flag

```text
CTF{0h_s0_y0u_kn0w_h0w_t0_expl01t_mus1_t00_huh!?_c9c4ad670ecbd791}
```
