---
layout: post
title: "toxicwaste"
date: 2026-06-06
categories: [Crypto]
difficulty: Medium
platform: UNbreakable Romania 2026
tags: [kzg, pairings, elliptic-curves]
excerpt: "Breaking a KZG-style commitment setup by reconstructing the shuffled powers of alpha and forging valid proofs."
---

## Summary

This challenge was built around a KZG-style polynomial commitment scheme. The public setup shuffled the points corresponding to powers of `alpha`, which made the order appear unknown at first.

Because the curve was supersingular, Weil pairing could be used to recover the correct ordering. Once that was restored, the commitment polynomial could be reconstructed and the proof system could be forged.

## Analysis

The setup generated a secret `alpha` and a list of points and coefficients such that the polynomial `B(x)` satisfied `B(alpha) = 0`. That relation was the core weakness.

The shuffle only obscured the order of the public points. It did not destroy the algebraic structure. Pairing checks were sufficient to recover the chain `G1, alpha G1, alpha^2 G1, ...`.

## Exploitation

The solve path was:

1. Use Weil pairing to reconstruct the order of the shuffled points.
2. Rebuild the polynomial `B(x)` from the published coefficients.
3. Exploit the fact that `B(alpha) = 0`.
4. Forge valid-looking witnesses for chosen `z, y` pairs.
5. Submit enough evaluations to force the server into an invalid high-degree interpolation and reveal the flag.

The important algebraic insight was that the commitment scheme assumed the public order was fixed and trustworthy. It wasn’t.

## Flag

`flag{Alph4_h4s_t0_b3_1nc1n3r4t3d_947a1a1e8895d3d483ab}`
