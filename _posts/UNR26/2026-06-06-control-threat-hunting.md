---
layout: post
title: "Control"
date: 2026-06-06
categories: [Threat Hunting]
difficulty: Medium
platform: UNbreakable Romania 2026
tags: [sysmon, windows, threat-hunting]
excerpt: "A Windows event investigation that reconstructs persistence, execution, privilege escalation, and the final credential-theft chain."
---

## Summary

This was a Windows threat-hunting exercise based on exported event logs. The task was to reconstruct an attack chain from the first user interaction through persistence, execution, privilege escalation, and the final suspicious process tree.

The answers were pulled from Sysmon and Security logs by correlating process creation, registry changes, and command-line evidence.

## Analysis

The most useful telemetry was:

- Sysmon Event ID 1 for process creation
- Sysmon Event ID 10 for process access
- Sysmon Event ID 13 for registry changes

The chain became clear once those records were linked together:

- the payload started as `MicrosoftUpdate.cpl`
- the execution path used `explorer.exe -> control.exe -> rundll32.exe`
- persistence was set through a `Run` registry key
- user enumeration followed with PowerShell
- escalation happened through `RunasCs` and then `GodPotato`

## Exploitation

The relevant answers were:

1. `MicrosoftUpdate.cpl`
2. `10.13.52.111:8888`
3. `explorer.exe-control.exe-rundll32.exe`
4. `msedge.exe`
5. `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`
6. `powershell.exe -Command Get-LocalUser`
7. `RunasCs.exe steve.stevens P@ssw0rd "rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"`
8. `GodPotato-NET4.exe -cmd "cmd.exe /c rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"`
9. `SeImpersonatePrivilege`
10. `C:\Users\Public\explorer.exe`

The important point is that all of those answers came from the same timeline, not isolated log lines.

## Flag

`Q1: MicrosoftUpdate.cpl`
`Q2: 10.13.52.111:8888`
`Q3: explorer.exe-control.exe-rundll32.exe`
`Q4: msedge.exe`
`Q5: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`
`Q6: powershell.exe -Command Get-LocalUser`
`Q7: RunasCs.exe steve.stevens P@ssw0rd "rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"`
`Q8: GodPotato-NET4.exe -cmd "cmd.exe /c rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"`
`Q9: SeImpersonatePrivilege`
`Q10: C:\Users\Public\explorer.exe`
