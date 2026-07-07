---
layout: post
title: "Rebuilding"
date: 2026-07-07
categories: [Reverse Engineering]
difficulty: Easy
platform: HackTheBox
tags: []
excerpt: "Reversing an ELF binary to recover a hidden XOR-encrypted password."
---

## Analysis

First, I checked the file type and extracted the readable strings:

```bash
$ file rebuilding
rebuilding: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked

$ strings rebuilding | grep -i "password\|correct\|incorrect"
The password is correct
The password is incorrect
Password length is incorrect
Missing required argument
Preparing secret keys
```

The binary expects one argument and checks whether it matches the correct password.

Loading the binary into Ghidra, I found the `main` function:

```c
undefined8 main(int param_1, long param_2)
{
    int __c;
    size_t sVar1;
    undefined8 uVar2;
    int local_14;
    int local_10;
    int local_c;

    if (param_1 != 2) {
        puts("Missing required argument");
        exit(-1);
    }

    local_14 = 0;
    sVar1 = strlen(*(char **)(param_2 + 8));

    if (sVar1 == 0x20) {  // Password must be 32 characters
        for (local_10 = 0; local_10 < 0x20; local_10 = local_10 + 1) {
            // Visual feedback (progress dots)
            for (local_c = 0; local_c < 6; local_c = local_c + 1) {
                if (local_c == local_10 % 6) {
                    __c = 0x2e;  // '.'
                } else {
                    __c = 0x20;  // space
                }
                putchar(__c);
            }
            fflush(stdout);

            // XOR comparison
            local_14 = local_14 +
                (uint)((byte)(encrypted[local_10] ^ key[local_10 % 6]) ==
                      *(byte *)((long)local_10 + *(long *)(param_2 + 8)));

            usleep(200000);
        }
        puts("");

        if (local_14 == 0x20) {
            puts("The password is correct");
            uVar2 = 0;
        } else {
            puts("The password is incorrect");
            uVar2 = 0xffffffff;
        }
    } else {
        puts("Password length is incorrect");
        uVar2 = 0xffffffff;
    }
    return uVar2;
}
```

The password validation logic works as follows:

1. The password must be exactly 32 characters long.
2. Each character is XORed with a key byte.
3. The key is 6 characters long and is repeated cyclically.
4. The encrypted data is stored in an array called `encrypted`.
5. The comparison performed is:

```text
encrypted[i] XOR key[i % 6] == user_input[i]
```

## Exploitation

We first need to find the encrypted data and the key, then XOR them to recover the password.

The encrypted data is stored at address `0x00301020`:

```asm
Address     Bytes
00301020    29 38 2b 1e 06 42 05 5d
00301028    07 02 31 10 51 08 5a 16
00301030    31 42 0f 33 0a 55 00 00
00301038    15 1e 1c 06 1a 43 13 59
00301039    14
```

The key appears to be stored immediately after the encrypted data at address `0x00301042`, where the string `humans` is located.

I used CyberChef to XOR the encrypted bytes (from hex) with this key:

![flag1]({{ '/assets/img/htb/key1.png' | relative_url }})

The output was just garbage, so I continued analyzing the binary. After some more investigation, I discovered another function that is not called from `main`, where the real key is initialized:

```c
void _INIT_1(void)
{
    puts("Preparing secret keys");
    key[0] = 'a';
    key[1] = 'l';
    key[2] = 'i';
    key[3] = 'e';
    key[4] = 'n';
    key[5] = 's';
    return;
}
```

The actual key is `aliens`.

Using this key instead, the XOR operation reveals the correct password:

![flag2]({{ '/assets/img/htb/key2.png' | relative_url }})

## Flag

`HTB{h1d1ng_c0d3s_1n_c0nstruct0r5}`