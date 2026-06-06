---
layout: post
title: "Unholy Land"
date: 2026-06-06
categories: [Forensics, Malware, OSINT]
difficulty: Medium
platform: UNbreakable Romania 2026
tags: [jq, suricata, json]
excerpt: "Mining a Suricata eve.json log with jq to recover protocol counts, totals, and the most common DNS hosts."
---

## Summary

This was a log-analysis challenge built around a large `eve.json` file from Suricata. The job was to extract several answers from telemetry by counting flow events and ranking DNS hosts.

The work was mostly about using the right `jq` filters and avoiding double-counting across event types.

## Analysis

The useful event type was `flow`, because alerts and HTTP/DNS records could refer to the same traffic. By filtering on protocol first and then counting the resulting lines, the answers could be derived directly from the log.

For the DNS question, I counted queried hostnames and sorted them by frequency to get the top three values.

## Exploitation

The solve path was:

1. Count TCP, UDP, and IPv6-ICMP flow events with `jq`.
2. Count all compact JSON records for the total event count.
3. Extract `.dns.queries[].rrname` values.
4. Sort and count the hostnames to get the most frequent ones.

The exact commands from the write-up were:

```bash
jq -c 'select(.event_type=="flow" and .proto=="TCP")' eve.json | wc -l
jq -c 'select(.event_type=="flow" and .proto=="UDP")' eve.json | wc -l
jq -c 'select(.event_type=="flow" and .proto=="IPv6-ICMP")' eve.json | wc -l
jq -c '.' eve.json | wc -l
jq -c 'select(.event_type=="dns") | .dns.queries[].rrname' eve.json | sort | uniq -c | sort -nr | head -3
```

## Answers

1. `UNR{3391, 2452, 15}`
2. `UNR{15551}`
3. `UNR{ncs.roblox.com, users.roblox.com, edge.microsoft.com}`
