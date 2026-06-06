---
layout: post
title: "Relay in the Noise"
date: 2026-06-06
categories: [Forensics, Network]
difficulty: Hard
platform: UNbreakable Romania 2026
tags: [pcap, ax25, aprs, zlib]
excerpt: "Decoding a noisy PCAP by stripping KISS framing, recovering APRS bulletins, and decrypting the final payload."
---

## Summary

At first glance, this PCAP looked like radio noise and decoy traffic. The real payload was hiding in the last stream, which carried KISS-framed AX.25/APRS messages rather than ordinary UDP application data.

The challenge was to identify the structure, decode the bulletin fragments, and turn the final ciphertext into readable text.

## Analysis

The capture contained 314 UDP frames. The first chunk was noise, the second chunk was a deliberate decoy, and the last chunk contained the useful traffic. The meaningful frames were wrapped in KISS delimiters (`0xC0`) and then encoded as AX.25 frames.

After removing the KISS wrapper and decoding the AX.25 headers, the payloads revealed APRS bulletin messages. Those bulletins contained fragments of a Base32 blob, but they also embedded the key-derivation rule.

The important clue was the grid/SSID relationship:

- grid locator: `FN31pr`
- SSID: `9`
- seed text: `fn31pr|9`

That seed was used to generate the keystream for the final XOR step.

## Exploitation

The solve path was:

1. Export the UDP payloads with `tshark`.
2. Identify the KISS/AX.25 segment.
3. Decode the bulletin fragments and concatenate them.
4. Base32-decode the blob into ciphertext.
5. Generate the SHA-256 keystream blocks from the seed.
6. XOR the ciphertext and decompress the result with `zlib`.

The relevant decoding pipeline:

```python
import base64, hashlib, zlib
seed = b"fn31pr|9"
chunks = [
    "IDQ4TVGWTBWZ","KAO4XDIUCOBH","5N5TTSJ2AU5B","3VJH62ZYAAKA","Y3ZIXF64WXEP",
    "7ROLYTNENRCS","2BBQRJXFOABS","FT7NWEANE6EA","RKRMBFJ3CLDN","UGELST6IVAEZ",
    "OLTCN4GR56ZE","7N4QBIQBD6JX","SXGURNDWX5E2","ZUXTQ3MIKM3O","2DJLMZJSZQDH",
    "KH7KU5MJYNTU","CO7CGNQ6ZUYQ"
]
```

The final decompressed message contained the flag.

## Flag

`UNR{4x25_p47h5_4nd_6r1d_5qu4r35_73ll_7h3_570ry_2fee56dc8f22f6a7}`
