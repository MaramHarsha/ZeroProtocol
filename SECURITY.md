# Authorized use

ZeroProtocol is tooling for **authorized** security testing. Three situations qualify:

1. A bug bounty or vulnerability disclosure program you are enrolled in, testing only the assets
   its published scope lists.
2. An engagement with a written scope and a signed authorization.
3. An asset you own.

Nothing else. "It was probably fine" is not authorization, a brand name in a hostname is not
ownership, and a public program page does not authorize the infrastructure behind an in-scope
website.

## How that is enforced

The boundary lives in `.zeroprotocol/scope.yaml` and is checked by `bin/zp-scope`, which every
traffic-sending skill calls:

```
0  in scope and confirmed by a human   -> proceed
1  out of scope                        -> refuse
3  scope file exists but unconfirmed   -> passive recon only
4  no scope file                       -> stop
```

Deny wins over allow. No rule matched means deny. Any error means deny. `zp-scope confirm` refuses
an empty scope, an empty authorization statement, and patterns like `*` or `0.0.0.0/0`.

Only a person can confirm a scope. Claude is instructed to ask for the authorization in the user's
own words and record those words, never to confirm on the user's behalf.

## Deliberate limits

ZeroProtocol stops at proof and omits the weaponized half of the usual toolkit. It does not
implement, and contributions should not add:

- remote shells, persistence, or post-exploitation pivoting
- mass or bulk scanning across a host list
- use of any credential discovered during testing
- data exfiltration beyond the single record, key or file that proves the issue
- denial-of-service, volumetric, or resource-exhaustion testing
- destructive proof: password changes, account creation, deletion of data you did not create,
  overwriting existing files or objects
- automated report submission

`skills/zp-cve-2026-41940/SKILL.md` documents the reasoning in detail for a CVSS 10.0 pre-auth
bypass, and that reasoning applies to every skill added later.

## Reporting a problem in ZeroProtocol itself

Open an issue, or for anything sensitive contact the repository owner directly. If you find that a
skill encourages an unsafe action, that is a bug and worth reporting as one.
