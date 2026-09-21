---
layout: post
title: "Gnome Breaker"
date: 2026-09-21
categories: [Forensics]
platform: DefCamp CTF 2026
tags: [forensics, gnome-keyring, john, python]
excerpt: "Fixing a keyring extraction error, cracking the login password, and recovering the secret stored inside."
---

## Summary

Gnome Breaker gave us an extracted Linux filesystem and a hint about saved passwords. I found the flag in the user's GNOME Keyring, but getting it out took an extra step: the installed `keyring2john` helper was extracting the wrong bytes.

Once I fixed the extraction, a dictionary attack recovered the password and I could decrypt the stored secret.

## Analysis

### Finding the keyring

The description mentioned Wi-Fi and login passwords, so I started with the user's home directory:

```bash
rg --files --hidden home etc var tmp
```

The files that stood out were:

```text
home/masquerade/.bash_history
home/masquerade/Documents/notes.txt
home/masquerade/Downloads/setup_notes.txt
home/masquerade/.local/share/keyrings/default
home/masquerade/.local/share/keyrings/default.keyring
home/masquerade/.local/share/keyrings/login.keyring
home/masquerade/.local/share/keyrings/user.keystore
```

The shell history gave me a good reason to start with `login.keyring`:

```bash
ls
cd .local/share/keyrings
xxd login.keyring | head
nmcli connection show
cat /etc/os-release
sudo apt update
htop
```

I checked the notes and logs for a password, but most of the text was repeated filler. There wasn't an obvious credential to use.

Running `file` on the keyring directory identified two AES-encrypted GNOME keyrings:

| File | Name | Hash iterations | Items |
| --- | --- | --- | --- |
| `login.keyring` | Login | 1603 | 1 |
| `default.keyring` | Default | 900 | 1 |

The file named `default` was just a text file containing `default`. The header of `login.keyring` confirmed the format:

```text
00000000: 476e 6f6d 654b 6579 7269 6e67 0a0d 000a  GnomeKeyring....
00000010: 0000 0000 0000 0005 4c6f 6769 6e00 0000  ........Login...
```

### Why the first extraction was wrong

John the Ripper supports GNOME Keyring, so I tried its extraction helper:

```bash
keyring2john home/masquerade/.local/share/keyrings/login.keyring
```

It produced this record:

```text
home/masquerade/.local/share/keyrings/login.keyring:$keyring$4a24e2c4bd9f555c*1603*16*0*00000000000000010000000a7864673a
```

The salt and iteration count looked right. The ciphertext didn't: it was only 16 bytes long, and its final bytes decoded to `xdg:`. That string is part of the public attribute name `xdg:schema`.

I checked the installed `/usr/share/john/keyring2john.py`. After the main header, it skipped eight bytes and took the next 16 as ciphertext. These files have public item metadata before the encrypted payload, so that fixed offset landed in the wrong place.

The parser needed to follow the file structure instead:

```text
Magic and version
Keyring name
Timestamps, flags and lock timeout
Iteration count and salt
Reserved fields
Item count
Public item metadata and attributes
Encrypted payload length
Encrypted payload
```

Integers are big-endian. Strings start with a four-byte length, with `0xffffffff` representing a null string. Each item's attributes must be read before moving on to the ciphertext length.

After parsing those fields, I got:

| File | Salt | Iterations | Payload offset | Payload size |
| --- | --- | --- | --- | --- |
| `login.keyring` | `4a24e2c4bd9f555c` | 1603 | `0x9b` | 160 bytes |
| `default.keyring` | `d272cc2faa9d5690` | 900 | `0xd4` | 208 bytes |

John expects the extracted data in this format:

```text
filename:$keyring$salt*iterations*ciphertext_size*0*ciphertext_hex
```

## Exploitation

### Extracting the correct data

I used the following script for extraction and decryption. Save it as `analysis/solve.py` inside the challenge directory. It needs PyCryptodome; the cracking step also needs John with support for the `keyring` format.

```bash
mkdir -p analysis
python3 -m venv .venv
./.venv/bin/python -m pip install pycryptodome
```

```python
from pathlib import Path
import struct
import hashlib
import re
import sys
from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parent.parent

class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0
    def take(self, n):
        value = self.data[self.pos:self.pos+n]
        assert len(value) == n
        self.pos += n
        return value
    def u32(self):
        return struct.unpack('>I', self.take(4))[0]
    def string(self):
        n = self.u32()
        return None if n == 0xffffffff else self.take(n)

def parse(path):
    r = Reader(path.read_bytes())
    assert r.take(16) == b'GnomeKeyring\n\r\x00\n'
    assert r.take(4) == bytes(4)
    name = r.string()
    r.take(24)
    iterations = r.u32()
    salt = r.take(8)
    r.take(16)
    items = r.u32()
    for _ in range(items):
        r.take(8)
        for _ in range(r.u32()):
            r.string()
            typ = r.u32()
            if typ == 0:
                r.string()
            elif typ == 1:
                r.u32()
            else:
                raise ValueError(typ)
    ciphertext = r.take(r.u32())
    assert r.pos == len(r.data)
    return salt, iterations, ciphertext

def decrypt(path, password):
    salt, iterations, ciphertext = parse(path)
    digest = hashlib.sha256(password.encode() + salt).digest()
    for _ in range(iterations-1):
        digest = hashlib.sha256(digest).digest()
    plaintext = AES.new(digest[:16], AES.MODE_CBC, digest[16:]).decrypt(ciphertext)
    assert hashlib.md5(plaintext[16:]).digest() == plaintext[:16], 'Wrong password'
    out = ROOT / 'analysis' / (path.name + '.decrypted')
    out.write_bytes(plaintext)
    print(path.name, 'password:', password, 'plaintext:', repr(plaintext))

if __name__ == '__main__':
    paths = sorted((ROOT / 'home/masquerade/.local/share/keyrings').glob('*.keyring'))
    if len(sys.argv) > 1:
        for path in paths:
            try:
                decrypt(path, sys.argv[1])
            except AssertionError as exc:
                print(path.name, exc)
    else:
        hashes = []
        for path in paths:
            salt, iterations, ciphertext = parse(path)
            hashes.append(f'{path.name}:$keyring${salt.hex()}*{iterations}*{len(ciphertext)}*0*{ciphertext.hex()}')
        (ROOT / 'analysis/keyrings.hash').write_text('\n'.join(hashes) + '\n')
        words = {'password', '123456', 'masquerade', 'gnome', 'admin', 'letmein', 'qwerty'}
        for directory in ('home', 'etc', 'var', 'tmp'):
            for path in (ROOT / directory).rglob('*'):
                if path.is_file():
                    words.update(re.findall(r'[\x21-\x7e]{4,}', path.read_bytes().decode('latin1')))
                    words.update(re.findall(r'[a-zA-Z0-9_!@#$.-]{4,}', path.read_bytes().decode('latin1')))
        (ROOT / 'analysis/candidates.txt').write_text('\n'.join(sorted(words)) + '\n')
        print('\n'.join(hashes))
```

Without an argument, the script creates the John records and a candidate wordlist from the supplied files:

```bash
./.venv/bin/python analysis/solve.py
```

### Cracking the password

I first tried the 622 candidates collected from the filesystem:

```bash
OMP_NUM_THREADS=4 john --format=keyring \
  --wordlist=analysis/candidates.txt \
  --pot=analysis/john.pot \
  --session=analysis/gnome analysis/keyrings.hash
```

None worked. I switched to `rockyou.txt`:

```bash
OMP_NUM_THREADS=4 john --format=keyring \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  --pot=analysis/john.pot \
  --session=analysis/rockyou analysis/keyrings.hash
```

After roughly two minutes and twenty seconds, John recovered the login keyring password:

```text
masquerade2k     (login.keyring)
```

The password was already in the dictionary, so I didn't need any mangling rules. The saved result was:

```bash
john --show --format=keyring --pot=analysis/john.pot analysis/keyrings.hash
```

```text
login.keyring:masquerade2k

1 password hash cracked, 1 left
```

### Decrypting the secret

I used [John's keyring implementation](https://github.com/openwall/john/blob/bleeding-jumbo/src/keyring_fmt_plug.c) to reproduce the decryption. The derivation starts with `SHA256(password || salt)` and hashes the digest again until the stored iteration count is reached. The first 16 bytes of the final digest become the AES key; the remaining 16 become the CBC IV.

The decrypted buffer begins with an MD5 digest of everything after it. That gives the script a way to check the password before saving the plaintext:

```python
assert hashlib.md5(plaintext[16:]).digest() == plaintext[:16]
```

I then ran:

```bash
./.venv/bin/python analysis/solve.py masquerade2k
```

`default.keyring` failed the password check, but `login.keyring` decrypted successfully. Its plaintext starts with the integrity digest, followed by the item label and secret:

```text
00000000: f651 01e1 87db 7d4c 1868 ce85 69c4 58c0  .Q....}L.h..i.X.
00000010: 0000 0004 466c 6167 0000 0020 4543 5343  ....Flag... ECSC
00000020: 7b43 306e 6772 6174 735f 796f 755f 6172  {C0ngrats_you_ar
00000030: 655f 4147 6e6f 6d65 4661 6e7d 0000 0000  e_AGnomeFan}....
```

The label is `Flag`, and the next length field is `0x20`: a 32-byte secret. I could read both with the same parser:

```bash
./.venv/bin/python - <<'PY'
from pathlib import Path
from analysis.solve import Reader

plaintext = Path("analysis/login.keyring.decrypted").read_bytes()
reader = Reader(plaintext[16:])
print("Label:", reader.string().decode())
print("Secret:", reader.string().decode())
PY
```

```text
Label: Flag
Secret: ECSC{C0ngrats_you_are_AGnomeFan}
```

That was all I needed from the keyring. There was no reason to keep cracking the second file.

## Flag

`ECSC{C0ngrats_you_are_AGnomeFan}`
