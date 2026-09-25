---
name: zp-cloud
description: ZeroProtocol hunter for cloud misconfiguration reachable from outside - object storage, metadata credentials, IAM blast radius, exposed orchestration and CI surfaces. Use when S3/GCS/Azure blob URLs appear, when a bucket may be public, when SSRF reached a metadata endpoint, when a cloud credential was found, or when Kubernetes, Docker, or a container registry is exposed. Reasons about blast radius without ever using a discovered credential.
---

# zp-cloud - the estate behind the app

**Phase:** 5 | **Gate:** **active.** `zp-scope check <host>` must exit 0 for every cloud host you
touch. Exit 1 refuse · 3 stop · 4 stop.

**Two rules that override everything else in this skill:**

1. **Never authenticate with a credential you discovered.** Not once, not "just to check the
   identity". `aws sts get-caller-identity` with someone else's key is unauthorized access to
   their cloud account. The retrievability is the finding.
2. **A cloud resource is not in scope because the app references it.** An S3 bucket, a shared
   registry, a managed service - each needs its own decision from `zp-scope` step 7. Cloud
   estates are shared, and the bucket may belong to a vendor.

---

## Procedure

**1. Inventory the cloud surface the app reveals.**

```bash
grep -ohE 'https?://[a-z0-9.-]+\.(s3[.-][a-z0-9-]*\.?amazonaws\.com|s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|r2\.cloudflarestorage\.com|digitaloceanspaces\.com|oss-[a-z-]+\.aliyuncs\.com)[^"'"'"' ]*' \
  surface/urls.txt js/*.js 2>/dev/null | sed -E 's#(https?://[^/]+).*#\1#' | sort -u
grep -ohE '[a-z0-9.-]{3,63}\.s3[.-][a-z0-9.-]*amazonaws\.com' js/*.js 2>/dev/null | sort -u
```

**2. Object storage - test read, list and write separately.** They are three different findings.

```bash
B=bucket-name
curl -sk -o /dev/null -w 'anon GET    %{http_code}\n' "https://$B.s3.amazonaws.com/"
curl -sk "https://$B.s3.amazonaws.com/?list-type=2&max-keys=5" | head -c 600   # listing
curl -sk -X PUT --data 'zp-canary-91234' -o /dev/null -w 'anon PUT    %{http_code}\n' \
  "https://$B.s3.amazonaws.com/zp-write-test-91234.txt"
curl -sk -o /dev/null -w 'ACL         %{http_code}\n' "https://$B.s3.amazonaws.com/?acl"
```

| Response | Meaning |
|---|---|
| `200` + `<ListBucketResult>` | **public listing.** Read the first few keys only |
| `403 AccessDenied` | bucket exists, private. Not a finding |
| `404 NoSuchBucket` | claimable -> `zp-takeover` |
| `200` on PUT | **public write.** Critical - anyone can plant content the app serves |
| `200` on `?acl` | ACL readable - often shows `AllUsers` grants |

If PUT succeeds: **delete your test object immediately** (`curl -X DELETE`), and say in the report
that you wrote one canary file and removed it. Never overwrite an existing key - that is
destruction, and on a bucket serving the app's JavaScript it is a supply-chain attack.

Permutations for finding buckets, without any tool:

```bash
for s in dev staging stage test qa prod backup backups api assets static cdn media \
         uploads files data logs private internal public reports exports; do
  for pat in "$D-$s" "$s-$D" "$D.$s" "${D%%.*}-$s" "$s.${D%%.*}"; do
    c=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "https://$pat.s3.amazonaws.com/")
    [ "$c" != "404" ] && echo "$c $pat"
  done
done
```

GCS: `https://storage.googleapis.com/<bucket>/` and `?prefix=&maxResults=5`.
Azure: `https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list`.

**3. Metadata credentials via SSRF.** See `zp-ssrf` for the delivery; this is what to do after.

If you retrieve a credential, the sequence is: **stop, redact, report.**

```
retrieved:  {"AccessKeyId":"ASIA…","SecretAccessKey":"…","Token":"…"}
evidence:   keep the first 4 characters of the key id and the JSON shape. Redact the rest.
report:     "IMDSv1 is reachable via SSRF at <endpoint>; temporary credentials for role
             <role-name> were returned. I did not use them. Please rotate."
```

The role name alone lets the operator assess blast radius, and you can read it from the metadata
path (`/iam/security-credentials/`) without touching the credential. That is the right amount of
proof.

**4. Reason about blast radius from the outside - no API calls.** What you can legitimately say:

```
role name from the metadata path          instance profile -> usually EC2/ECS task role
bucket names the app references           what data the role likely reaches
service hostnames in the bundle           which managed services are in play
the app's own behaviour                   does it upload, transcode, send mail, assume roles
```

Write the blast radius as an *assessment*, clearly labelled as inference, not as something you
verified. Triagers prefer an honest "this role appears to have access to X, please confirm" over
an unauthorized enumeration.

**5. Exposed orchestration and infrastructure surfaces.**

```bash
for u in "https://$H:10250/pods" "https://$H:6443/api/v1/namespaces" \
         "https://$H:2375/version" "https://$H:2376/version" \
         "http://$H:9200/_cat/indices?v" "http://$H:5601/api/status" \
         "http://$H:8500/v1/catalog/services" "http://$H:2379/version" \
         "http://$H:9090/api/v1/targets" "http://$H:15672/api/overview" \
         "http://$H:8080/metrics" "http://$H:9000/minio/health/live"; do
  printf '%-52s ' "$u"
  curl -sk -o /dev/null -w '%{http_code}\n' --max-time 8 "$u"
done
```

An unauthenticated Docker API (`2375`) or kubelet (`10250`) is container escape and cluster
compromise. Confirm with **one read-only call** (`/version`, `/pods`) and stop - do not create
containers, do not exec, do not list secrets.

**6. CI/CD and registry exposure.**

```bash
curl -sk "https://$H/v2/_catalog"                          # open Docker registry
curl -sk "https://$H/.git/config" | head -5                 # source exposure
for p in .github/workflows .gitlab-ci.yml Jenkinsfile .circleci/config.yml \
         .env.production terraform.tfstate .terraform/terraform.tfstate; do
  c=$(curl -sk -o /dev/null -w '%{http_code}' "https://$H/$p"); [ "$c" = "200" ] && echo "200 /$p"
done
```

`terraform.tfstate` is the jackpot and the trap: it routinely contains plaintext credentials.
Confirm the file is readable and note *that* it contains credential fields - **do not** extract
or catalogue them.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| public bucket listing with customer data | **confirmed.** High to Critical by sensitivity |
| public bucket listing of public assets (images, CSS) | Low or not a finding - check what is in it |
| anonymous write to a bucket the app serves from | **Critical** - supply-chain. Delete your canary |
| `403` on the bucket | exists, private. Killed |
| metadata credentials retrievable via SSRF | **Critical.** Report retrievability, never use them |
| Docker API or kubelet unauthenticated | **Critical.** One read-only call as proof |
| Elasticsearch/Kibana/Consul open with data | High to Critical |
| Prometheus/metrics open | Low to Medium - usually information disclosure |
| `terraform.tfstate` readable | Critical. Note the presence of secrets, do not harvest them |
| open registry catalogue | Medium to High - image names leak architecture; pulling images is usually out of scope |
| bucket belongs to a third-party vendor | **not your finding.** Back to `zp-scope`, and tell the program |

---

## High-value patterns

- **A bucket serving the app's JS with anonymous write** - stored XSS on every user, via the CDN.
- **`*-backup` or `*-dev` buckets** - production data, no access control, nobody watching.
- **IMDSv1 still enabled** behind an SSRF-able feature - the classic path to full account compromise.
- **`terraform.tfstate` in a web root** - the whole infrastructure plus credentials.
- **An open Docker socket on a "dev" host** that shares a VPC with production.
- **A pre-signed URL with a long expiry** in an email or API response - check the `X-Amz-Expires`.
- **Cross-tenant object paths** in a shared bucket (`/uploads/<tenant>/…`) -> `zp-idor`.

---

## Pitfalls

- **Using a discovered credential.** The line that must not be crossed here.
- **Overwriting an existing object** to prove write access. Write a uniquely-named canary, then delete it.
- **Enumerating a whole bucket** to show impact. Five keys and the listing header.
- **Assuming a referenced bucket is in scope.**
- **Creating containers or exec-ing** through an exposed Docker API.
- **Listing Kubernetes secrets.** One `/pods` read is the proof.
- **Harvesting credentials out of `tfstate`.**
- **Reporting an open bucket of public marketing images** as Critical.
- **Forgetting to delete your canary** and leaving a writable-bucket artifact behind.
- **Pulling images** from an open registry - usually far beyond what the program authorized.

---

## Hand off to

`404 NoSuchBucket` -> `zp-takeover`. SSRF as the delivery path -> `zp-ssrf`.
Keys found in a bundle -> `zp-js-secrets`. Cross-tenant object paths -> `zp-idor`.
Bucket-hosted uploads -> `zp-upload`. Recovered source or IaC -> `zp-code-audit`.
Anything confirmed -> `zp-triage`, `zp-report`, and for metadata credentials or an open Docker
socket, report the same hour.
