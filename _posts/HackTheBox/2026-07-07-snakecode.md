---

layout: post
title: "Snakecode"
date: 2026-07-07
categories: [Reverse Engineering]
difficulty: Easy
platform: HackTheBox
tags: []
excerpt: "Extracting layered Python bytecode obfuscation through base64 decoding, zlib decompression, and marshal deserialization."
---

## Analysis

In this Reverse Engineering challenge, we are provided with a Python bytecode file:

```bash
$ file chall.pyc
chall.pyc: python 2.7 byte-compiled
```

I decided to use `uncompyle6` to decompile the Python bytecode:

```bash
$ uncompyle6 chall.pyc
# uncompyle6 version 3.9.3
# Python bytecode version base 2.7 (62211)
# Decompiled from: Python 3.13.12
# Embedded file name: ./snake_obf.py
import marshal, types, time

ll = types.FunctionType(
    marshal.loads(
        ('YwEAAAABAAAABQAAAEMAAABzNAAAAHQAAGoBAHQCAGoDAHQEAGQBAIMBAGoFAHwAAGoGAGQCAIMB\n'
         'AIMBAIMBAHQHAIMAAIMCAFMoAwAAAE50BAAAAHpsaWJ0BgAAAGJhc2U2NCgIAAAAdAUAAAB0eXBl\n'
         'c3QMAAAARnVuY3Rpb25UeXBldAcAAABtYXJzaGFsdAUAAABsb2Fkc3QKAAAAX19pbXBvcnRfX3QK\n'
         'AAAAZGVjb21wcmVzc3QGAAAAZGVjb2RldAcAAABnbG9iYWxzKAEAAAB0AQAAAHMoAAAAACgAAAAA\n'
         'cwcAAAA8c3RkaW4+dAoAAABsb2FkTGFtYmRhAQAAAHQAAAAA\n').decode('base64')
    ),
    globals()
)

i0 = ll('eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5JFiXkp+bkajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGAC+nBJh\n')
i1 = ll('eJxLZoACJiB2BuJiLiBRwsCQwsjQzMgQrAES9ythA5LJpUXFqcUajCB5kKL4+Mzcgvyikvh4DZAB\nCKKYHUjYFJekZObZlXCA2DmJuUkpiXaMEKMZGADEORJ1\n')
f0 = ll('eJxLZmRgYABhJiB2BuJiXiBRw8CQxcCQwsjQzMgQrAGS8ssEEgwaIJUl7CAiMzc1v7QEIsAMJMoz\n8zTASkBEMUiJTXFJSmaeXQkHiJ2TmJuUkmgHVg5SAQBjWRD5\n')
# ... many more encoded strings ...

def snake(w):
    r = i0()
    c = i1()
    f0(w)
    d = (0, 1)
    p = [(5, 5)]
    pl = 1
    s = 0
    l = None
    while 1:
        p, d, pl, l, s, w, c, r = m2(p, d, pl, l, s, w, c, r)
        time.sleep(0.4)
    return

i1().wrapper(snake)
return
```

The decompiled code reveals a heavily obfuscated Python program. The important part is the loader function:

```python
ll = types.FunctionType(
    marshal.loads(
        ('<base64 blob>').decode('base64')
    ),
    globals()
)
```

This function dynamically reconstructs Python functions from encoded data.

Every variable assigned through the loader, for example:

```python
i0 = ll('eJxLZoACJiB2BuJiLiBR...')
```

goes through the following process:

```
Base64 decoding
        ↓
zlib decompression
        ↓
marshal.loads()
        ↓
Python code object
        ↓
types.FunctionType()
        ↓
Executable Python function
```

The challenge hides all important logic inside these dynamically generated functions.

---

## Extraction

To extract the hidden functions, I modified the `ll` loader so that instead of creating functions, it writes the decoded bytecode to files:

```python
import zlib
import base64

def ll(name, data):
    with open("out/" + name, "wb") as fp:
        fp.write(zlib.decompress(base64.b64decode(data)))

```

Then I replaced each function creation with a call to the modified loader:

```python
i0 = ll("i0", 'eJxLZoACJiB2BuJiLiBR...')
i1 = ll("i1", 'eJxLZoACJiB2BuJiLiBR...')
# ... repeat for all encoded functions
```

After extracting all the hidden code objects, I converted them back into Python bytecode files and decompiled them:

```bash
$ for x in out/*; do python marshal-to-pyc.py $x; done
```

After reviewing the resulting files, one of the extracted functions (`a2.py`) contained the flag construction logic:

```python
f = [
    'H', 'T', 'B', '{', 'S', 'u', 'P', '3',
    'r', '_', 'S', '3', 'C', 'R', 't', '_',
    'S', 'n', '4', 'k', '3', 'c', '0', 'd',
    '3', '}'
]

return ''.join(f)
```

The flag characters are stored directly inside the list. Joining them together reveals the final flag:

```python
>>> ''.join(f)
'HTB{SuP3r_S3CRt_Sn4k3c0d3}'
```

---

## Flag

```
HTB{SuP3r_S3CRt_Sn4k3c0d3}
```
