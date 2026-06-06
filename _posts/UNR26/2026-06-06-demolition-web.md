---
layout: post
title: "demolition"
date: 2026-06-06
categories: [Web]
difficulty: Hard
platform: UNbreakable Romania 2026
tags: [xss, csp, unicode]
excerpt: "A filter bypass that turns a Unicode-normalized tag into a working script injection against the admin bot."
---

## Summary

This challenge combined a Flask backend with a Go sanitization service. The goal was to steal the admin bot’s cookie, but the Python layer tried to block script tags with an ASCII-only regex.

The important mistake was a mismatch between validation and normalization. A tag name that looked non-dangerous to the Python filter could still be normalized into a real `<script>` tag later by the Go sanitizer.

## Analysis

The backend filter used an ASCII-only regular expression to reject `<script>`. The Go side then canonicalized tag names using Unicode-aware case folding. That meant a visually similar character could survive the first stage and become active JavaScript in the second.

The exploit therefore was not about bypassing CSP directly at first. The first step was just getting a script-like payload to survive the sanitization pipeline.

## Exploitation

The working payload used the long `s` character (`ſ`) to evade the Python regex while still normalizing to `script` later. Once JavaScript execution was available in the bot’s browser, the remaining problem was exfiltration under CSP.

The payload strategy was to build a `<meta http-equiv="refresh">` tag dynamically and send `document.cookie` to a webhook URL. That avoided a straightforward `fetch` to an untrusted domain.

A useful detail from the source:

```python
SCRIPT_FENCE_RE = re.compile(r"<\s*/?\s*script", re.IGNORECASE | re.ASCII)
```

That filter only sees ASCII, which is why the Unicode normalization path mattered.

## Flag

`CTF{7b5d3e42e57dab38821b5215138825098cbe965c67c131b6c64be1805626481d}`
