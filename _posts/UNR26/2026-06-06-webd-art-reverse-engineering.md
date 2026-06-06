---
layout: post
title: "webd-art"
date: 2026-06-06
categories: [Reverse Engineering]
difficulty: Hard
platform: UNbreakable Romania 2026
tags: [wasm, dart, xor]
excerpt: "Reverse engineering a Dart-compiled WebAssembly module to recover the secret output without brute force."
---

## Summary

This web challenge used a Dart-compiled WebAssembly module as its core logic. The page loaded `main.wasm`, invoked the exported function, and then rendered either a normal success path or a hidden branch that revealed a secret.

The interesting part was the secret-generation logic, which used a custom hash and an XOR stream based on `fmix32`. The path to the flag was therefore to reverse the output, not brute-force the input.

## Analysis

The provided files were a normal web bundle: HTML, JavaScript glue, CSS, and the WASM binary. Static inspection showed the app instantiating the module and calling into the main export.

Inside the module, the validation compared the computed hash against internal constants. That meant the hidden output could be recovered by understanding the derivation rather than searching the input space.

## Exploitation

The solve path was:

1. Inspect the WASM module and identify the comparison logic.
2. Recover the internal constants.
3. Rebuild the XOR stream generated from `fmix32`.
4. Reverse the stream to recover the secret string.
5. Extract the flag from the decoded output.

Relevant entry point from the page:

```html
<script type="module">
import { compileStreaming } from "./main.mjs";
const app = await compileStreaming(fetch("main.wasm"));
const instance = await app.instantiate({});
instance.invokeMain();
</script>
```

The important part was that the “secret” was generated deterministically and could be reversed directly.

## Flag

`CTF{7h3_w3b_15_4_l13_rng_15_d373rm1n15m}`
