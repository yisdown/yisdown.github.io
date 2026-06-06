---
layout: post
title: "Riga Crypto"
date: 2026-06-06
categories: [Reverse Engineering, Crypto]
difficulty: Hard
platform: UNbreakable Romania 2026
tags: [nodejs, aes-cbc, reverse-engineering]
excerpt: "Reverse engineering a native Node.js library to recover a custom transform and decrypt a file-encrypted flag."
---

## Summary

This challenge buried the real logic inside a native library that was called from obfuscated JavaScript. The package contained two `flag.enc` files, but only one of them belonged to the actual challenge path.

The encryption flow was layered: a custom byte transform, a fixed marker, PKCS#7 padding, and finally AES-CBC with fixed ASCII key and IV values. Once the native transform was understood, the file decrypted cleanly.

## Analysis

The first job was identifying the real artifact. The unpacked package contained `extracted/unpacked/flag.enc`, which turned out to be the relevant ciphertext. The smaller root-level file was just a decoy.

The shared library exported three interesting functions:

- `EncryptFileHex`
- `DeriveRoundFingerprint`
- `DescribeCipherSuite`

`EncryptFileHex` was the core entry point. It did not encrypt a raw string; it read bytes from a file path, transformed them, and returned the final ciphertext as hex.

That distinction mattered because it explained why direct string tests looked inconsistent at first.

## Exploitation

The solve path was:

1. Decrypt the outer AES-CBC layer.
2. Remove the fixed marker.
3. Recover the internal `T(msg)` transform.
4. Reverse the stages in the opposite order.
5. Recover the original plaintext.

The fixed cryptographic values were:

```text
Key = "021b49755fb4961a40f3a539ee80fa8f"
IV  = "8cc46e76876a55c1"
Marker = "67e672f4049b06ee"
```

Once the native transform was inverted, the plaintext revealed the flag.

## Flag

`UNR{cu_m454l4r174-m1r3454_54-1_713_d3_1mp4r473454_f4abc8120c3d2a57}`
