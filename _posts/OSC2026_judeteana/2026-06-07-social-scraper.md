---
layout: post
title: "social-scraper"
date: 2026-06-07
categories: [OSINT]
difficulty: Medium
platform: OSC2026 judeteana
tags: [OSINT]
excerpt: "Following a trail of social media accounts."
---

## Summary

### Challenge Description

> "Detectivul andre1ut vrea să o ia pe urmele lui Sherlock Holmes. Acesta și-a făcut un cont cu numele de utilizator andre1ut pe platforma de socializare a Cerului Albastru și vrea să îți transmită un mesaj secret. Folosește-te de indiciile primite în cerință pentru a putea ajunge la răspunsul final."

The goal of this challenge is to conduct a social media investigation based on a username and follow the provided clues to recover the final flag.

## Analysis

We are only given a username, `andre1ut`, and a hint referring to a social media platform called BlueSky.

After searching for the username, I found the following profile:

![BlueSky Profile]({{ '/assets/img/osc26j/andre1ut.png' | relative_url }})

The profile contained another username, `iamsherlockjr`, which appeared to be the next clue.

After searching for this username across different platforms, I found an account on Hacker News:

![Hacker News Profile]({{ '/assets/img/osc26j/iamsherlockjr.png' | relative_url }})

In the account description, there was an encoded message. Looking at the text, it appeared to be encoded using the ROT13 cipher.

After decoding it, I obtained the following message:

```text
FLAG-UL REAL ESTE NUMELE PLATFORMEI MELE DE MATEMATICA, TRECUT PRIN SHA256
```

The description also contained a link to a TikTok account named `mathclutch`, which is likely the mathematics platform referenced in the decoded message.

Hashing the string `mathclutch` using SHA256 produces the final flag.

## Flag

`CTF{37b98a8ea0f2adfea9eb1e9cc3bcce4c8f58187191f40ae1f77916b59e343099}`
