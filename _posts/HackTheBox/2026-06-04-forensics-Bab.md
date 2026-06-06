---
layout: post
title: "Bab"
date: 2026-06-06
categories: [Forensics, Malware]
difficulty: Hard
platform: CyberEdu
tags: [forensics, malware]
excerpt: "A test web security write-up."
---

## Summary

This is a test post for the Web category.

---

## Recon

```python
elf = ELF('./pwn')

context.arch = 'amd64'
cyberedu = '34.159.85.111:31989'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()


def malloc(size, data):
#select
    p.recvuntil(b": ")
    p.sendline(b"1")
#size
    p.recvuntil(b": ")
    p.sendline(size)
#data
    p.recvuntil(b": ")
    p.send(data)
    
    
    
```

## Exploitation

Your content here...

## Flags

user.txt ✓ root.txt ✓
