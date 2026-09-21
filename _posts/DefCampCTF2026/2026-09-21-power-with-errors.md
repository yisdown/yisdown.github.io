---
layout: post
title: "Power with Errors"
date: 2026-09-21
categories: [Crypto]
platform: DefCamp CTF 2026
tags: [crypto, matrices, lattices, ciphertext-only, xor]
excerpt: "Recovering fifteen XOR keys from noisy matrix powers using commutators and lattice reduction."
---

## Summary

Power with Errors encrypted the flag with fifteen XOR keys, then leaked each key as a small error added to a matrix power. The useful detail was that each group of three outputs came from the same base matrix.

Powers of one matrix commute. I used that relation to recover two keys from each group with a lattice, then solved for the third using a smaller, linear system.

## Analysis

### Reading the challenge

The files were `chall.sage`, `params`, five `testcase_*.in` files, and `enc`. The description asked:

> Have you heard about ciphertext-only attacks?

The supplied parameters were:

```text
p=289681150111530694174556323703782825681
n=10
t=5
c=3
```

Here is the generator:

```python
from Crypto.Util.number import *
import secrets
def xor(A,B):
  return bytes([a^^b for (a,b) in zip(A,B)])

p=getPrime(128)
n=10
t=5
c=3
F=open("params","w")
F.write(f"{p=}\n{n=}\n{t=}\n{c=}")
F.close()
flag=open("flag.txt",'rb').read()
assert(len(flag)<=n*n)
flag+=b"\x00"*(n*n-len(flag))
for T in range(t):
  A=random_matrix(GF(p),n,n)
  out=[]
  for _ in range(c):
    key=b"\x00"+os.urandom(n*n-1)
    print(list(key))
    flag=xor(key,flag)
    U=pow(A,secrets.randbelow(p)).list()
    U=[a+b for (a,b) in zip(U,key)]
    out.append(U)
  F=open(f"testcase_{T}.in","w")
  F.write(f"{out}")
  F.close()

F=open(f"enc","wb")
F.write(flag)
F.close()
```

The `^^` operator is Sage's XOR syntax. The script pads the flag to 100 bytes, then XORs it with a fresh key on each iteration. There are five batches of three keys, and every key starts with a zero byte.

For each batch, the script also chooses a random `10 × 10` matrix over `GF(p)`. It raises that matrix to three random powers and adds the corresponding key bytes to the flattened results.

Reshaping a key into a matrix `K`, each public output is:

```text
U = A^r + K  (mod p)
```

The entries of `A^r` are field elements modulo a 128-bit prime, while the entries of `K` are only bytes. If I could recover those small errors, I could undo all fifteen XORs on the flag.

### Using the commutator

For matrices `X` and `Y`, the commutator is `[X,Y] = XY - YX`. Two powers of the same matrix commute, so the clean outputs satisfy:

```text
[A^r, A^s] = 0
```

For two public outputs `U` and `V`, subtracting their keys must restore that property:

```text
[U - K1, V - K2] = 0

[U, V] - [U, K2] - [K1, V] + [K1, K2] = 0

[U, K2] + [K1, V] - [U, V] = [K1, K2]  (mod p)
```

The left side is linear in the unknown key bytes. The right side is quadratic, but it contains only products of small values. That gave me a linear expression with a small residual to target with a lattice.

There is also a useful constraint: `K1[0,0] = K2[0,0] = 0`. A scalar multiple of the identity commutes with every matrix, so fixing one diagonal entry removes that scalar ambiguity for each key.

## Exploitation

### Recovering the first two keys

I started by centering each unknown byte around zero. For every entry except the first, I subtracted `128` from the public matrix:

```python
u = [
    [(x - (128 if j else 0)) % P for j, x in enumerate(a)]
    for a in raw
]
```

The new errors are `E[i,j] = K[i,j] - 128`, with `E[0,0] = 0`. Their unknown entries lie between `-128` and `127`. For the centered public matrices, the equation becomes:

```text
[U', E2] + [E1, V'] - [U', V'] = [E1, E2]  (mod p)
```

Each error matrix contributes 99 unknowns, giving 198 in total. The commutator has 100 entries, but its trace is zero, so I left out the last diagonal equation and kept 99 equations.

At position `(i,j)`, the linear expression is:

```text
sum over k of:

    U'[i,k] × E2[k,j] - E2[i,k] × U'[k,j]
  + E1[i,k] × V'[k,j] - V'[i,k] × E1[k,j]
```

Every coefficient comes from the public matrices. Each entry of the residual `[E1,E2]` is a sum of ten differences of small products. Even the simple bound `20 × 128² = 327680` is tiny compared with `p`.

I put the unknown entries into a row vector `e`, the coefficients into a `198 × 99` matrix `C`, and the selected entries of `[U',V']` into `d`. The lattice basis was:

```text
        198 columns   99 columns   1 column

      [ 256 × I          C            0     ]
B  =  [    0           p × I          0     ]
      [    0            -d          32768   ]
```

This is a 298-dimensional lattice. Using the correct errors to combine its rows produces a vector of the form:

```text
(256 × e, e × C - d + p × q, 32768)
```

The vector `q` accounts for reduction modulo `p`. For the correct `e`, the middle coordinates can equal the small quadratic residual. The factor `256` balances the error coordinates against those residuals, while the last coordinate embeds the constant term.

I first tried the full reduction with `fpylll`, but it was slow. Switching to [flatter](https://github.com/keeganryan/flatter) brought the larger reductions to roughly two minutes per batch in my run.

After reduction, I looked for rows whose final coordinate was `32768` or `-32768`. I then recovered the bytes, checked they were in range, and verified that subtracting them made the two public matrices commute exactly modulo `p`.

### Recovering the third key

With one clean matrix recovered, the third key was easier. Let `M` be that clean matrix, `W'` the centered third output, and `E3` its unknown error:

```text
[M, W' - E3] = 0

[M, E3] = [M, W']  (mod p)
```

This time the equations are exactly linear in the 99 unknown entries of `E3`. I used Gaussian elimination modulo `p` to express the pivot variables in terms of the free ones, then built a second lattice to find a solution with small entries.

That lattice has 99 variable coordinates and one embedding coordinate. The pivot rows contain multiples of `p`, the free-variable rows encode homogeneous solutions, and the last row holds a particular solution with embedding value `256`.

Reducing this 100-dimensional lattice with `fpylll` recovered the third key. I checked all three pairs of corrected matrices in every batch before using the keys to decrypt anything.

### Solver

Save this as `solve.py` beside the challenge files. The `keys_*_2.json` files cache the first two keys from each batch; `keys_*_3.json` stores all three.

```python
#!/usr/bin/env python3
"""Recover byte noise from commuting matrix powers, then undo the XORs."""
import ast
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from fpylll import IntegerMatrix, LLL

P = 289681150111530694174556323703782825681
N = 10
WEIGHT = 256
EMBED = 32768

def comm(a, b):
    return [sum(a[i*N+k]*b[k*N+j] - b[i*N+k]*a[k*N+j]
                for k in range(N)) % P for i in range(N) for j in range(N)]

def recover_with_known(clean, raw):
    shifted = [(x-(128 if k else 0)) % P for k,x in enumerate(raw)]
    rhs = comm(clean,shifted)
    matrix = []
    for i in range(N):
        for j in range(N):
            row = []
            for k in range(1,N*N):
                r,s = divmod(k,N)
                row.append(((clean[i*N+r] if j==s else 0)
                           -(clean[s*N+j] if i==r else 0))%P)
            matrix.append(row+[rhs[i*N+j]])
    pivots = []
    for col in range(99):
        r = len(pivots)
        chosen = next((i for i in range(r,100) if matrix[i][col]),None)
        if chosen is None: continue
        matrix[r],matrix[chosen] = matrix[chosen],matrix[r]
        inv = pow(matrix[r][col],-1,P)
        matrix[r] = [x*inv%P for x in matrix[r]]
        for i in range(100):
            if i != r and matrix[i][col]:
                factor = matrix[i][col]
                matrix[i] = [(a-factor*b)%P for a,b in zip(matrix[i],matrix[r])]
        pivots.append(col)
    assert all(not any(row) for row in matrix[len(pivots):])
    free = [i for i in range(99) if i not in pivots]
    lattice = IntegerMatrix(100,100)
    for i in pivots: lattice[i,i] = P
    for f in free:
        lattice[f,f] = 1
        for r,col in enumerate(pivots): lattice[f,col] = -matrix[r][f]
    for r,col in enumerate(pivots): lattice[99,col] = matrix[r][-1]
    lattice[99,99] = 256
    LLL.reduction(lattice)
    for r in range(100):
        if abs(lattice[r,99]) != 256: continue
        sign = int(lattice[r,99])//256
        key = [0]+[int(lattice[r,i])*sign+128 for i in range(99)]
        if not all(0<=x<=255 for x in key): continue
        if any(comm(clean,[(a-b)%P for a,b in zip(raw,key)])): continue
        return key
    raise RuntimeError('Third-key recovery failed')

def recover(filename, count=2):
    raw = ast.literal_eval(Path(filename).read_text())[:count]
    u = [[(x - (128 if j else 0)) % P for j, x in enumerate(a)] for a in raw]
    pairs = [(a,b) for a in range(count) for b in range(a+1,count)]
    # The final diagonal equation follows from the zero trace of a commutator.
    equations = [(a,b,i,j) for a,b in pairs for i in range(N) for j in range(N)
                 if (i,j) != (N-1,N-1)]
    equations = equations[:int(os.environ.get('EQUATIONS',len(equations)))]
    variables = [(a,k) for a in range(count) for k in range(1,N*N)]
    nv, ne = len(variables), len(equations)
    size = nv+ne+1
    lattice = IntegerMatrix(size,size)
    for v,(a,k) in enumerate(variables):
        lattice[v,v] = WEIGHT
        r,s = divmod(k,N)
        for e,(b,c,i,j) in enumerate(equations):
            val = 0
            if a == b:
                if i == r: val += u[c][s*N+j]
                if j == s: val -= u[c][i*N+r]
            if a == c:
                if j == s: val += u[b][i*N+r]
                if i == r: val -= u[b][s*N+j]
            lattice[v,nv+e] = val % P
    cs = {(a,b):comm(u[a],u[b]) for a,b in pairs}
    for e,(a,b,i,j) in enumerate(equations):
        lattice[nv+e,nv+e] = P
        lattice[size-1,nv+e] = -cs[a,b][i*N+j]
    lattice[size-1,size-1] = EMBED
    print(f'{filename}: LLL dimension {size}',flush=True)
    start=time.time()
    flatter = os.environ.get('FLATTER')
    if flatter:
        encoded = '['+'\n'.join('['+' '.join(map(str,row))+']' for row in lattice)+']'
        result = subprocess.run([flatter],input=encoded,text=True,capture_output=True,check=True)
        entries = list(map(int,re.findall(r'-?\d+',result.stdout)))
        assert len(entries)==size*size
        lattice = IntegerMatrix.from_matrix([entries[i*size:(i+1)*size] for i in range(size)])
    else:
        LLL.reduction(lattice,delta=float(os.environ.get('DELTA','0.99')))
    print(f'LLL done in {time.time()-start:.1f}s',flush=True)
    for row in range(size):
        last = int(lattice[row,size-1])
        if abs(last) != EMBED: continue
        sign = last//EMBED
        keys = [[0]*100 for _ in range(count)]
        for v,(a,k) in enumerate(variables):
            keys[a][k] = int(lattice[row,v])*sign//WEIGHT+128
        if not all(0 <= x <= 255 for key in keys for x in key): continue
        clean = [[(x-k)%P for x,k in zip(a,key)] for a,key in zip(raw,keys)]
        if not all(not any(comm(clean[a],clean[b])) for a,b in pairs): continue
        print(f'Recovered {count} keys!',flush=True)
        return keys
    norms = [sum(int(x)**2 for x in lattice[r]) for r in range(min(size,10))]
    print('First norms:',[round(x.bit_length()/2,1) for x in norms],flush=True)
    raise RuntimeError('No verified key found')

if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='all':
        plaintext = bytearray(Path('enc').read_bytes())
        for t in range(5):
            cache = Path(f'keys_{t}_2.json')
            keys = json.loads(cache.read_text()) if cache.exists() else recover(f'testcase_{t}.in')
            cache.write_text(json.dumps(keys))
            raw = ast.literal_eval(Path(f'testcase_{t}.in').read_text())
            clean = [(a-b)%P for a,b in zip(raw[0],keys[0])]
            keys.append(recover_with_known(clean,raw[2]))
            restored = [[(a-b)%P for a,b in zip(u,k)] for u,k in zip(raw,keys)]
            assert all(not any(comm(restored[i],restored[j])) for i in range(3) for j in range(i))
            Path(f'keys_{t}_3.json').write_text(json.dumps(keys))
            for key in keys:
                for i,x in enumerate(key): plaintext[i] ^= x
            print(f'Batch {t}: all three keys verified',flush=True)
        Path('flag.txt').write_bytes(plaintext.rstrip(b'\x00'))
        print(bytes(plaintext).rstrip(b'\x00').decode(),flush=True)
        sys.exit(0)
    t = int(sys.argv[1]) if len(sys.argv)>1 else 0
    count = int(sys.argv[2]) if len(sys.argv)>2 else 2
    keys = recover(f'testcase_{t}.in',count)
    Path(f'keys_{t}_{count}.json').write_text(json.dumps(keys))
```

Install the dependencies and run it with:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install fpylll cysignals
./.venv/bin/python solve.py all
```

To use `flatter` for the larger reductions, build it following its repository instructions and set the executable path:

```bash
export FLATTER=/path/to/flatter
export OMP_NUM_THREADS=2
export OPENBLAS_NUM_THREADS=1
./.venv/bin/python solve.py all
```

The five batches are independent, so I could also run their larger reductions separately:

```bash
for t in 0 1 2 3 4; do
    ./.venv/bin/python solve.py "$t" 2 > "solve_$t.log" 2>&1 &
done
wait
./.venv/bin/python solve.py all
```

With those keys cached, the final run recovered the remaining keys and decrypted the flag:

```text
Batch 0: all three keys verified
Batch 1: all three keys verified
Batch 2: all three keys verified
Batch 3: all three keys verified
Batch 4: all three keys verified
CTF{7ff8b019311e3394808f55ebaa1e9c7cef048a6c8681074d0cda751a85dbe9df}
```

As a final check, I padded the recovered flag back to 100 bytes and XORed it with all fifteen keys. The result matched `enc` exactly.

## Flag

`CTF{7ff8b019311e3394808f55ebaa1e9c7cef048a6c8681074d0cda751a85dbe9df}`
