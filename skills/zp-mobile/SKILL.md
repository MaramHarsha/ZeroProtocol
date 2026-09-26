---
name: zp-mobile
description: ZeroProtocol hunter for Android and iOS application security in a bounty context. Use when an APK, AAB or IPA is in scope, when asked to analyse a mobile app, when hunting hardcoded secrets in a binary, exported components, deep-link hijacking, insecure storage or certificate pinning, or when pivoting from a mobile app to its backend API. Static analysis first, because it is free and it finds the API surface that is the real prize.
---

# zp-mobile - the app is a map to the API

**Phase:** 5 | **Gate:** unpacking and reading a binary is **offline** work and needs no gate.
Touching any endpoint you discover is **active** - `zp-scope check` exit 0 first, every time.

**The most valuable thing in a mobile app is not a mobile vulnerability.** It is the backend API
it talks to: undocumented endpoints, looser authorization than the web app, and the API keys it
ships. Hunt the binary to reach the server.

---

## Procedure

**1. Get the package legitimately.** From the program's own link, the Play Store/App Store, or a
build the program supplies. Note the exact version and build number - findings are version-bound.

```bash
unzip -o app.apk -d apk/ >/dev/null && ls apk/
```

**2. Decompile.**

```bash
jadx -d out/ app.apk                 # readable Java - always prefer this
apktool d app.apk -o apktool-out/    # smali + a decoded AndroidManifest.xml
# iOS: unzip the .ipa, then
unzip -o app.ipa -d ipa/ && ls ipa/Payload/*.app/
plutil -convert xml1 -o - ipa/Payload/*.app/Info.plist
strings -a ipa/Payload/*.app/<Binary> | sort -u > ios-strings.txt
```

**3. Read the manifest - it is the attack surface in one file.**

```bash
grep targetSdkVersion apktool-out/apktool.yml           # decides what "exported" means below
grep -oE '<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*' apktool-out/AndroidManifest.xml
python3 -c 'import re                                   # implicit exports: filter, no attribute
x=open("apktool-out/AndroidManifest.xml").read()
for m in re.finditer(r"<(activity|service|receiver|provider)\b([^>]*)>(.*?)</\1>", x, re.S):
    if "<intent-filter" in m.group(3) and "android:exported" not in m.group(2):
        print(m.group(1), m.group(2).strip()[:120])'
grep -oE 'android:(allowBackup|debuggable|usesCleartextTraffic)="true"' apktool-out/AndroidManifest.xml
grep -A3 'intent-filter' apktool-out/AndroidManifest.xml | grep -oE 'android:scheme="[^"]*"' | sort -u
grep -oE 'android:networkSecurityConfig="[^"]*"' apktool-out/AndroidManifest.xml
cat apktool-out/res/xml/network_security_config.xml 2>/dev/null
```

| Manifest finding | Impact |
|---|---|
| `exported="true"` activity with no permission | any installed app can launch it - bypass login screens, reach internal views |
| `exported="true"` content provider | direct read/write of app data by any app |
| `exported="true"` broadcast receiver | injectable intents, sometimes privileged actions |
| `<intent-filter>` and **no** `android:exported` at all | exported by default when `targetSdkVersion` < 31 - the case the plain grep cannot see, and where most real findings live |
| `allowBackup="true"` | `adb backup` extracts the app's private data on older Android |
| `debuggable="true"` in a release build | full runtime access. Rare and serious |
| `usesCleartextTraffic="true"` | HTTP traffic permitted |
| `cleartextTrafficPermitted="true"` in the NSC | same, per-domain |
| custom `android:scheme` | deep-link surface - see step 5 |

Read the target SDK before judging any of this. Below 31 a filtered component that omits
`android:exported` *is* exported, and the attribute is simply absent from the manifest - so the
`exported="true"` grep alone under-reports the surface. At 31 and above the attribute is mandatory
whenever a filter is present, so its absence is a build error rather than an export. State the
target SDK in the report; it is what decides the impact.

**4. Hunt secrets and the API surface.**

```bash
grep -rhoE '(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[0-9A-Za-z-]{10,})' out/ | sort -u
grep -rhoE 'https?://[a-zA-Z0-9._-]+\.[a-z]{2,}[a-zA-Z0-9._/-]*' out/ | sort -u > mobile-hosts.txt
grep -rniE '(api[_-]?key|secret|password|token|bearer|client[_-]?secret)\s*=\s*"[^"]{12,}"' out/ | head -40
cat out/resources/res/values/strings.xml 2>/dev/null | grep -iE 'key|secret|token|url|api'
grep -rn 'BuildConfig' out/ | grep -iE 'key|secret|token' | head
```

`res/values/strings.xml` and `BuildConfig` are where developers put keys they believe are hidden
because the app is compiled. They are not hidden.

**Classify before reporting:** a Google Maps key or a Firebase config is *designed* to ship in the
client - the finding there is missing key restrictions or open Firebase rules, not the key's
presence. An `sk_live`, an `AKIA`, or a backend admin key is a genuine Critical. Never use any of
them.

**5. Deep links and exported components - the reachable-by-another-app surface.**

```bash
# every scheme/host the app claims
grep -B2 -A6 'intent-filter' apktool-out/AndroidManifest.xml | grep -oE 'android:(scheme|host|pathPrefix)="[^"]*"'
# reach it (on your own device/emulator)
adb shell am start -W -a android.intent.action.VIEW -d "myapp://reset?token=zp91234"
adb shell am start -n com.target.app/.internal.AdminActivity          # exported without permission?
adb shell content query --uri content://com.target.app.provider/users # exported provider
```

The high-value pattern: a deep link that carries an auth token or performs a state change, and
does not validate its origin. `myapp://oauth/callback?code=…` reachable by any installed app is
authorization-code theft.

iOS equivalents: `CFBundleURLSchemes` in `Info.plist`, plus
`com.apple.developer.associated-domains` for universal links.

**6. Insecure storage** - on your own device, with your own account. `run-as` is not the general
case: it only works on a package built `android:debuggable="true"`, or on a userdebug/eng build.
Against the Play Store release APK step 1 told you to obtain it fails with `run-as: package not
debuggable`. The three routes are `run-as` on a debuggable build, `adb root`/`su` on **your own**
rooted device or emulator, and `adb backup`/`bmgr` where `allowBackup="true"` permits it - name
which one you used in the report, because it is the precondition that caps the severity.

```bash
adb shell run-as com.target.app ls -R /data/data/com.target.app/    # debuggable builds only
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
# iOS: the app container's Library/Preferences/*.plist, Documents/, and the Keychain
```

Look for: session tokens or passwords in `shared_prefs`, an unencrypted SQLite database with PII,
PII in logs (`adb logcat | grep -i token`), and sensitive data in the WebView cache. A token in
plaintext `shared_prefs` is a finding on a rooted or backup-accessible device - state that
precondition honestly, because it caps the severity.

**7. Transport security and pinning.**

```bash
grep -rn 'checkServerTrusted\|ALLOW_ALL_HOSTNAME_VERIFIER\|TrustAllCerts\|setHostnameVerifier\|X509TrustManager' out/ | head
grep -rn 'certificatePinner\|sslSocketFactory\|NSAppTransportSecurity\|NSAllowsArbitraryLoads' out/ ipa/ 2>/dev/null | head
```

An empty `checkServerTrusted` is accepting any certificate - a real finding. Pinning *present* is
not a vulnerability; it is an obstacle, and bypassing it (Frida/objection on your own device) is
a means to see the traffic, not a finding in itself.

**8. Pivot to the API - this is the point.**

```bash
sort -u mobile-hosts.txt | zp-scope filter > mobile-hosts-inscope.txt
```

Then take those endpoints through `zp-api`, `zp-idor`, `zp-authz` and `zp-jwt-oauth`. Mobile
backends are frequently a generation behind the web API in authorization rigour, and they are
much less picked over.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| live backend key (`sk_live`, `AKIA`, admin token) in the binary | **Critical.** Report, never use |
| Google Maps / Firebase / analytics key | not a finding by itself. Test restrictions and rules |
| exported activity bypassing authentication | confirmed. Show the `adb am start` and the resulting state |
| exported content provider returning user data | confirmed, High |
| deep link accepting an auth token without validation | confirmed, High to Critical |
| plaintext token in `shared_prefs` | confirmed, but state the rooted/backup precondition |
| `allowBackup="true"` alone | Low; Medium if it exposes credentials on a supported OS version |
| `debuggable="true"` in a production build | High |
| empty `checkServerTrusted` | confirmed MITM exposure, Medium to High |
| pinning present and you bypassed it on your own device | **not a finding.** It was your tooling |
| cleartext traffic permitted but everything uses HTTPS anyway | Low / informational |
| undocumented API endpoint found in the binary | discovery - the finding comes from testing it |
| hardcoded credentials that are already public or expired | killed |

**The most common junk mobile report:** "hardcoded API key" for a key that is meant to be public,
and "no certificate pinning" as a standalone vulnerability. Both read as inexperience.

---

## High-value patterns

- **The mobile API being looser than the web API** - the single best reason to do this work.
- **An admin or internal backend key shipped in the client.**
- **Deep link carrying an OAuth code or reset token** with no origin validation -> `zp-jwt-oauth`.
- **Exported activity landing past the login screen** - authentication bypass on the device.
- **Exported provider exposing the session database.**
- **A staging/debug host still in the release build** - often unauthenticated.
- **Firebase with open rules**, discovered via the config in the app -> `zp-api`.
- **A WebView with `addJavascriptInterface` and a loadable URL you control** - RCE-adjacent on Android.

---

## Pitfalls

- **Testing on someone else's device or account.** Your own device, your own accounts.
- **Using a discovered key.**
- **Reporting pinning bypass as a vulnerability.**
- **Reporting a public client key as a leaked secret.**
- **Omitting the precondition** for storage findings (root, backup, physical access) - it caps severity and triagers will notice if you hide it.
- **Skipping the manifest** and going straight to strings. The manifest is the surface.
- **Not version-pinning the finding.** Always state the exact app version and build.
- **Obtaining the APK from a third-party mirror** - it may be repackaged, and your finding will not reproduce.
- **Stopping at the app.** The API behind it is where the severity lives.

---

## Hand off to

Discovered endpoints -> `zp-api`, `zp-idor`, `zp-authz` (scope-checked first).
Deep-link token handling -> `zp-jwt-oauth`. Backend keys -> `zp-cloud` for blast radius, then
report. Firebase/Supabase configs -> `zp-api`. WebView sinks -> `zp-xss`.
Traffic inspection -> `zp-proxy`. Confirmed -> `zp-triage`, `zp-report`.
