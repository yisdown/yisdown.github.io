---
layout: post
title: "substrate"
date: 2026-06-06
categories: [Reverse Engineering]
difficulty: Hard
platform: UNbreakable Romania 2026
tags: [driver, unicorn, ioctl]
excerpt: "A Windows driver challenge solved by emulating the IOCTL handler and reconstructing the required 69-byte input."
---

## Summary

This challenge paired a user-mode executable with a kernel driver. The user-mode program talked to the driver through `DeviceIoControl`, and the driver validated a 69-byte buffer with a custom compare routine.

Instead of manually reversing every branch, I emulated the handler and reconstructed the expected payload byte by byte.

## Analysis

The two key files were `SubstrateUM.exe` and `SubstrateKM.sys`. Static analysis exposed the device path and the IOCTL flow, which made it clear where the validation lived.

The user-mode binary referenced the device name `\.\SubstrateDeviceLink`, and the driver implemented the actual check. That made the problem much better suited to emulation than to purely manual reverse engineering.

## Exploitation

The solve path was:

1. Identify the device and IOCTL used by the user-mode binary.
2. Emulate the driver handler in Unicorn.
3. Rebuild the required 69-byte buffer from the observed comparisons.
4. Feed the recovered buffer back into the binary.
5. Receive the flag once validation passed.

Useful static-analysis commands from the solve:

```bash
strings -n 5 SubstrateUM.exe
objdump -d SubstrateUM.exe
objdump -d SubstrateKM.sys
```

The important lesson here was that a driver check does not need to be solved by hand if the comparison logic can be emulated cleanly.

## Flag

`CTF{1c41e1d89f95c6c6b45f256f06e554f904257c884f683528302bacbde8b9484f}`
