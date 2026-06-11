---
layout: post
title: "shigehira"
date: 2026-06-11
categories: [Forensics]
difficulty: Easy
platform: OSC2026 nationala
tags: [forensics, network]
excerpt: "HTTP traffic analysis to extract malware downloads, user agents, and network indicators of compromise."
---

## Summary

In this forensics challenge, we are given a `fun.pcap` file and need to answer the following questions:

```bash
Q1. Specificați toate extensiile descărcate care au fost utilizate, în ordinea folosirii lor.
(Format: OSCN{extensii separate prin ',' fara spatii intre ele})

Q2. Care sunt User Agent-urile (în ordinea cronologică a marcajelor de timp) pentru fișierele care au fost instalate de dropper-ul găsit în pcap?
(Ex: OSCN{Postman/3.2-Aria2/1.2})

Q3. Identifică cei 2 producători de plăci de rețea (NIC) ai celor două dispozitive implicate în cele mai multe tentative de conexiune.
(Format: OSCN{Manufacturer1,Manufacturer2} - în ordine alfabetică, fără abrevieri, litere mici)

Q4. Care sunt cele 2 numere de port utilizate care încearcă să realizeze conexiuni post-infecție?
(În ordine crescătoare. Ex: OSCN{123,124})

Q5. Ce CVE utilizează variația malware-ului principal?
(Format: CVE-XXXX-XXXX, unde anul este mai mic decât 2020)
```

## Q1

Opening the file in Wireshark and filtering the packets to show only HTTP GET requests, we can identify the three file extensions that were downloaded:

![Git]({{ '/assets/img/osc26n/s_1.png' | relative_url }})

Answer:

`OSCN{x86,mips,mpsl}`

## Q2

Using the filter `http.request`, we can identify two User-Agent strings in packets 4 and 28324:

```http
GET /jaws HTTP/1.1
User-Agent: Wget/1.20.3 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 158.94.210.88
Connection: Keep-Alive


GET /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mpsl HTTP/1.1
Host: 158.94.210.88
User-Agent: curl/7.68.0
Accept: */*
```

Answer:

`OSCN{Wget/1.20.3-curl/7.68.0}`

## Q3

This question is fairly straightforward. We can use the filter `arp || eth.addr` or simply inspect the first two packets to identify the network interface card (NIC) manufacturers.

![Git]({{ '/assets/img/osc26n/s_h.png' | relative_url }})

![Git]({{ '/assets/img/osc26n/s_n.png' | relative_url }})

These correspond to the manufacturers **Hewlett-Packard** and **Netgear**.

Answer:

`OSCN{hewlett-packard,netgear}`


