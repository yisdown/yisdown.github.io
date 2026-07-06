---
layout: post
title: "Find The Easy Pass"
date: 2026-07-04
categories: [Reverse Engineering]
difficulty: Easy
platform: HackTheBox
tags: [Ghidra, Wine]
excerpt: "Using Wine and GDB to dynamically recover the password from a Windows executable."
---

## Analysis

The challenge provides a single executable:

```bash
$ ls
EasyPass.exe
```

Running the binary with Wine displays a simple password prompt.

```bash
$ wine EasyPass.exe
```

Entering any random password results in a "Wrong Password!" message.

![easy]({{ '/assets/img/htb/easypass1.png' | relative_url }})

Opening the file in Ghidra, we can search for the "Wrong Passwor!" string and find the main password checking function at 0x00454050. The decompiled code revealed the logic:

```c
FUN_00404628(*(uint **)(iVar7 + -0x28), *(uint **)(iVar7 + -4));
if ((bool)uVar8) {
    FUN_00427a30((uint *)"Good Job. Congratulations");
}
else {
    FUN_00427a30((uint *)"Wrong Password!");
}
```
The function FUN_00404628 performs the password comparison. Looking at the disassembly around the call:

```asm
00454118 call sub_40459c
0045411d lea edx, [ebp-0x28]
00454120 mov eax, dword [ebx+0x2f8]
00454126 call sub_433110
0045412b mov eax, dword [ebp-0x28]
0045412e mov edx, dword [ebp-0x4]
00454131 call do_check
00454136 jne 0x454144
00454138 mov eax, congrats
0045413d call showmsgbox
00454142 jmp 0x45414e
00454144 mov eax, password
00454149 call showmsgbox
```

Immediately before `do_check` is called, the program loads two pointers into `EAX` and `EDX`. One contains the user input while the other contains the expected password.

Rather than reversing the comparison function itself, it's easier to inspect these registers during execution.

## Exploatation

Since the binary runs correctly under Wine, I used **Wine-GDB** to debug it.

Start the program:

```bash
winedbg --gdb EasyPass.exe
```

Set a breakpoint immediately before the comparison function:

```gdb
Wine-gdb> break *0x0454131
Breakpoint 1 at 0x454131
```

Continue execution:

```gdb
Wine-gdb> continue
```

The password window appears. I entered a test password to reach the comparison.

Execution stops at the breakpoint.

Inspecting the registers:

```gdb
Wine-gdb> x/s $eax
0x1602444: "test"

Wine-gdb> x/s $edx
0x160366c: "fortran!"
```

`EAX` contains my input (`test`), while `EDX` contains the hardcoded password the program is expecting.

Therefore, the correct password is:

```text
fortran!
```

Running the executable again and entering this password displays the success message.

## Flag 

`HTB{fortran!}`
