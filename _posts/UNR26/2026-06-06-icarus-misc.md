---
layout: post
title: "Icarus"
date: 2026-06-06
categories: [Misc]
difficulty: Hard
platform: UNbreakable Romania 2026
tags: [python, sandbox, bytecode]
excerpt: "Bypassing a Python bytecode sandbox by abusing LOAD_FAST and leaking the exception output."
---

## Summary

This challenge exposed a Python service that accepted attacker-controlled hex, converted it to bytes, and executed the resulting data as bytecode inside a manually built `CodeType`. The intended defense was a small opcode allowlist and a stripped-down runtime, but the sandbox still leaked enough to be breakable.

The break came from two facts: `LOAD_FAST` was allowed, and runtime exceptions were returned to the client. That gave a way to reach frame-local objects, recover references to useful functions, and leak the flag through the traceback path.

## Analysis

The service looked restrictive on paper. The payload had to stay under 1000 bytes, remain valid UTF-8, and work with a very small opcode set. Dangerous builtins such as `eval`, `exec`, `open`, and `__import__` were removed, and `sys.modules` was cleared.

What the sandbox missed was that `LOAD_FAST` still lets bytecode read local variables from the current frame. In practice, that was enough to recover a dictionary-like object containing references to modules and builtins. Once that reference was obtained, the remaining problem was just turning it into file-system access.

The second mistake was exception handling. The runtime exposed internal error messages directly, which meant an exception could be used as an exfiltration channel.

## Exploitation

The exploit chain was short:

1. Use `LOAD_FAST` to access a frame-local dictionary.
2. Recover helper references such as `os.listdir`, `io.open`, and `vars`.
3. Enumerate the working directory to find the flag file.
4. Open and read that file.
5. Raise a `KeyError` so the content leaks in the traceback.

The interesting part of the solve was that the payload never needed to break the allowlist. It only needed to combine the instructions the sandbox already permitted.

Relevant constraints from the challenge:

- payload max: 1000 bytes
- valid UTF-8 only
- allowlist included `LOAD_FAST`
- standard streams were closed
- dangerous builtins were removed

## Flag

`CTF{f8059e1faa2644e3df29ef42de4dcd85}`
