---
layout: post
title: "social-god"
date: 2026-06-09
categories: [OSINT]
difficulty: Medium
platform: OSC2026 nationala
tags: [OSINT, social media]
excerpt: "An OSINT investigation that follows a chain of social media clues."
---

## Summary

### Challenge Description

> Detectivul andre1ut s-a întors cu un nou caz, de data aceasta fiind pe urmele cuiva suspicios! Trebuie să îl ajuți să găsească informații despre activitatea acestuia.

This is clearly an OSINT challenge focused on social media investigation, following the trail of the username `andre1ut`.

## Analysis

By performing a simple Google search for the username `andre1ut`, I found a GitHub account with the same name.

![Git]({{ '/assets/img/osc26n/andr_git.png' | relative_url }})

The account's bio contains an address, but it does not appear to be relevant to the challenge. Looking at the recent activity, I noticed several commits to a repository named `DetectivePlatform`, which is hosted using GitHub Pages.

After visiting the website, I found a post describing an investigation conducted by `andre1ut` involving someone named Jack Sparrow and a veterinary clinic located in Clejani.

![Det]({{ '/assets/img/osc26n/andr_det.png' | relative_url }})

Using the location mentioned in the post, I searched for veterinary clinics in Clejani and found a business named `SC DRMEDVET SRL`.

Inspecting the Google Maps reviews, I found a review written by Jack Sparrow. The review contained a reference to the Instagram account `@captainjacksparrowdelaclejani`.

![Rev]({{ '/assets/img/osc26n/andr_rev.png' | relative_url }})

I then viewed the Instagram profile using a third-party Instagram viewer and discovered that the flag was hidden in the account's bio.

![Ins]({{ '/assets/img/osc26n/andr_ins.png' | relative_url }})

## Flag

`CTF{83288eb3011a564e081f93614425a9d097bdf2bbab39885783e340d4a2fdaac7}`
