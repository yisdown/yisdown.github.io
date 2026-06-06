---
layout: post
title: "jumpy"
date: 2026-06-06
categories: [Reverse Engineering]
difficulty: Hard
platform: UNbreakable Romania 2026
tags: [binary-analysis, obfuscation, aes]
excerpt: "A stripped ELF that rewrites an encrypted file through a custom transform and hidden debug path."
---

## Summary

The challenge shipped a stripped ELF and a ciphertext file, `enc.sky`. Running the program against the file rewrote it in place, which made it clear the binary was performing a custom transformation rather than simply printing a flag.

The real work was reconstructing the transform, which mixed SHA-256, bit operations, and hidden branches that only became visible once the debug path was activated.

## Analysis

Initial triage showed that the binary imported SHA-256 routines and contained strings that hinted at block-wise processing. That pointed toward a bespoke encryption or packing pipeline.

The important clue was a hidden code path gated by an environment variable. Setting `X=1` enabled extra logging and exposed the internal block layout, which made the structure observable instead of opaque.

## Exploitation

The solve path was:

1. Confirm the binary rewrote `enc.sky` in place.
2. Enable the hidden debug path with `X=1`.
3. Recover the internal block and transform metadata.
4. Rebuild the transform stages and their inverse.
5. Apply the inverse to the rewritten file.

Relevant commands from the reverse engineering process:

```bash
file chall enc.sky
strings -n 6 chall
X=1 ./chall < enc.sky
```

The hidden block dump exposed the structure needed to finish the inverse transform.

## Flag

`UNBR{daca_faci_challu_esti_magnat_si_ai_furat_34_67_date_personales_boss}`
