# Issuing 100,000 short-lived certificates per second with limited HSM capacity

This is the answer to the architecture question in the assignment. The short
version: **the HSM protects the keys whose compromise would be catastrophic
and long-lived; it must not be on the hot path of every leaf signature.** The
hierarchy below keeps every long-lived private key inside an HSM, lets the
leaf signing rate scale with ordinary compute, and uses *key lifetime* rather
than *key location* to bound the blast radius of the software-held keys.

## 1. The numbers that shape the design

| Quantity | Value | Consequence |
|---|---|---|
| Target issuance rate | 100,000 certs/s (8.6 billion/day) | Must scale horizontally on commodity compute |
| ECDSA P-256 signing, network HSM (typical partition) | ~1,000–20,000 sig/s, 1–10 ms per call | 5–100 HSMs with zero headroom if every leaf is signed in-HSM |
| ECDSA P-256 signing, software (aws-lc / ring, one core) | ~30,000–60,000 sig/s | 100k/s is 3–4 cores of signing work |
| Cloud KMS asymmetric sign | ~$0.03 per 10k requests, hard per-key rate limits | ~$26,000/day at 100k/s, and throttled long before that |
| HSM session limits | tens to low hundreds per partition | A fleet of signers cannot each hold many sessions |

Even if the budget existed for 50+ HSMs, an HSM-per-leaf design couples
issuance availability to HSM availability and adds milliseconds of network
latency to each certificate. The security benefit is small: a leaf that lives
minutes to hours does not need the same protection as a key that anchors a
trust domain for a decade.

## 2. Hierarchy and trust boundaries

```
Root CA (offline HSM, ceremony only, 15–20 y)
└── Regional/policy intermediate CA (online HSM, non-exportable, 1–5 y)   ← this service
    └── Issuing CA  N  (per signer instance, software key, cert valid 24–72 h, rotated every 6–12 h)
        └── Leaf certificates (minutes–hours, signed in software at line rate)
```

**Root CA.** Key generated and held in an offline HSM (or a quorum-controlled
HSM partition that is only powered for ceremonies). It signs intermediate CA
certificates and the CRL for intermediates, nothing else. Its compromise is
the only unrecoverable event, so it is kept off every network.

**Intermediate CAs.** One or more per region (or per policy domain: workloads
vs. humans vs. devices), resident in online HSMs with `CKA_SENSITIVE=true`,
`CKA_EXTRACTABLE=false`, exactly as the keys in this service are provisioned.
They sign only *issuing CA* certificates and the small CRL that revokes
issuing CAs. Their HSM signing rate is therefore tiny (see §4), which is what
lets a handful of HSMs serve the whole platform. Constraints on the
intermediate certificate limit what a stolen issuing CA could do: `pathlen=1`,
name constraints on the trust domains it may issue for (e.g. only
`spiffe://customer-a/...` URIs), and EKU restrictions.

**Issuing CAs.** The novel tier. Each *signer instance* (an ordinary
autoscaled service) generates its own ECDSA P-256 key pair in memory at
start-up, sends a CSR to the intermediate signer (this service's API, fronting
the HSM), and receives an issuing CA certificate with `pathlen=0`, a validity
of 24–72 hours and the same name constraints. The private key never touches a
disk: it lives in locked, non-swappable, zeroized-on-drop memory, ideally inside
a TEE (Nitro Enclave, SEV-SNP or SGX) whose attestation document the
intermediate signer verifies before signing the CSR. Rotation is continuous:
a signer requests its next issuing certificate well before the current one
expires and overlaps them, so a brief HSM outage never stops issuance.

**Leaf certificates.** Signed by the issuing CA key in software. Validity is
short (the NHI use case: minutes to a few hours, matching workload lifetimes),
so revocation is "stop renewing" rather than CRL/OCSP at 8.6 billion entries a
day. The chain delivered to the workload is `leaf + issuing CA +
intermediate`; relying parties trust the root.

## 3. Should every leaf signature occur inside the HSM? No.

Arguments for signing leaves in the HSM are weaker than they look:

* **The attacker already has an oracle.** A compromised signer host can submit
  arbitrary CSRs to whatever signs leaves; whether the signature is computed
  in silicon or in RAM, the attacker mints certificates. What the HSM changes
  is only whether the *key* can be copied, and for a key that expires in
  hours, copying it buys little more than the oracle does.
* **It couples availability to the HSM.** A network partition or HSM firmware
  upgrade becomes an issuance outage for every tenant.
* **It does not scale economically.** The capacity table above puts the
  in-HSM design at tens of HSM partitions with no redundancy, versus about six
  for the hierarchy in §2 (two per region for HA), where HSM cost is driven by
  *availability* rather than throughput.

What *does* belong in the HSM: the intermediate keys (long-lived, high blast
radius), the KEKs used for wrapping, and any key whose compromise would
require a root ceremony to recover from.

## 4. Capacity arithmetic for the HSM tier

With 200 signer instances across 3 regions, each rotating its issuing CA
every 8 hours:

```
issuing-CA signatures/day = 200 signers × 3 rotations = 600
                          ≈ 0.007 signatures/second
```

Add an order of magnitude for autoscaling churn, canary rollouts and
pre-rotation overlap and the intermediates still see well under one signature
per second. HSM load in practice is dominated by health probes and wrapping
operations. A single HSM partition rated at 1,000 sig/s has three to four
orders of magnitude of headroom; the second partition per region exists for
availability, not capacity. This is why the session pool in this service is
sized for *backpressure* (bounded concurrency, acquire timeouts, 503 +
`Retry-After`) rather than for raw throughput: a thundering herd of signers
re-rotating after an incident must be shed, not queued without bound.

## 5. Key wrapping versus software generation for issuing keys

| Option | How | Pros | Cons |
|---|---|---|---|
| **A. Software-generated, never persisted** (recommended default) | Signer generates the key in memory; CSR signed by the intermediate in the HSM | Simplest; no key material at rest; loss on restart is harmless (issue a new one) | Key quality and origin are those of the host RNG/software; no "generated in a FIPS module" claim |
| **B. HSM-generated, wrapped out** | Intermediate signer generates the issuing key in the HSM with `CKA_EXTRACTABLE=true`, wraps it under a non-exportable KEK (`CKM_AES_KEY_WRAP_PAD`, demonstrated by this service), returns the blob; signer unwraps in software (or into a local PKCS#11 provider) | Key provably generated in the HSM; blobs can be stored for warm restarts and escrow; origin is auditable | Wrapping out is an export: the HSM only guarantees encryption at rest; unwrap in software needs a software copy of the KEK **or** a second HSM round trip per restart; more moving parts for a key that lives a day |
| **C. TEE-held issuing keys with attestation** | As A, but the key is generated inside an enclave and the intermediate signs the CSR only after verifying the attestation document | Strongest software option: key never visible to the host OS; signing cannot be moved off the attested code | Platform-specific; attestation verification becomes part of the CA policy engine |

The honest trade-off: B is attractive when compliance requires HSM-generated
keys or when warm restarts of signers matter; otherwise A (or C where the
platform allows it) is simpler and has strictly less key material at rest.
The wrap/unwrap round trip implemented in this service (`POST
/v1/keys/{kek}/wrap-roundtrip`) is exactly the primitive option B needs, and
its negative proofs (the KEK itself refuses to be wrapped or read) are the
property that makes the KEK a safe long-term anchor for those blobs.

## 6. Regional capacity, failover and trust distribution

* **Per region:** an HSM HA group of at least two partitions with replicated
  intermediate keys, two or more instances of this service in front of them,
  and an autoscaled fleet of signers. Regions are independent failure domains:
  each region's intermediate chains to the same root, so a workload can
  validate a certificate issued in any region without new trust material.
* **HSM outage:** signers keep issuing leaves with their current issuing CA
  until it expires; with 72-hour issuing certificates and 8-hour rotation the
  platform tolerates a multi-day HSM outage with no issuance impact. The
  rotation controller alarms long before that window closes.
* **Region outage:** DNS/anycast shifts clients to a healthy region; nothing in
  the trust chain changes.
* **Trust distribution:** relying parties get the root (and optionally pinned
  intermediates) through the existing trust bundle distribution mechanism (the
  same problem the proxy assignment solves for CA bundles). Issuing CA
  certificates travel in the chain and never need pre-distribution.
* **Revocation at this scale:** leaves expire instead of being revoked. An
  issuing CA is revoked by (1) the intermediate publishing a small CRL entry
  and (2) its short validity; relying parties that cannot fetch CRLs are still
  protected within hours. Intermediates are revoked by the root CRL during a
  ceremony.

## 7. Security implications by tier

| Compromise of | Blast radius | Containment |
|---|---|---|
| Leaf key | One workload identity for minutes–hours | Expiry; no action usually needed |
| Issuing CA key (one signer) | Can mint leaves in its name-constrained domain until the issuing cert expires (hours) | Per-signer keys limit it to one instance; intermediate CRL entry; attestation (option C) makes exfiltration impractical; every issued certificate is logged to an append-only transparency log so mis-issuance is detectable |
| Intermediate (HSM) | Would require abusing the HSM as an oracle; key cannot be copied | HSM audit logs, quorum-controlled admin operations, PIN handling as in this service (never in process args or logs), rotate via root ceremony and publish root CRL |
| Root | Catastrophic | Offline, ceremony-only, split-knowledge custody |

Additional controls that fall out of the design:

* **Signer hardening:** keys in locked, non-swappable memory with
  zeroize-on-drop; core dumps disabled; mTLS between signers and this service;
  the signer's own identity (SPIFFE SVID) is what authorizes it to request an
  issuing certificate, and it may only request one for its own region and
  trust domain.
* **Rate limiting and anomaly detection** on CSR requests per signer; an
  issuing CA that suddenly issues at 10× its baseline is rotated and
  investigated.
* **Policy enforcement at the intermediate signer:** name constraints, EKUs,
  maximum validity and attestation checks are enforced where the HSM key is
  used, so a compromised signer cannot widen its own authority.

## 8. Cost

HSM count is set by regions × HA, not throughput: three regions × two
partitions is six partitions (on the order of $80k–$120k/year as cloud HSMs,
or a few hundred thousand dollars capex on-prem), versus tens of partitions
for in-HSM leaf signing. Leaf signing at 100k/s is a few dozen cores of
commodity compute including API, TLS and logging overhead; the certificate
transparency/audit log and its storage (8.6 billion small records per day)
cost more than the signing fleet and should be designed with retention tied
to leaf lifetime.

## 9. Where this service fits

This repository implements the HSM-facing tier of §2: non-exportable keys,
bounded sessions with backpressure, a KEK with a demonstrated wrap/unwrap
workflow, and the observability needed to see pool saturation before it
becomes an issuance problem. The missing pieces for a production CA are the
X.509 policy layer (CSR validation, name constraints, attestation
verification) and the transparency log; both sit in front of this API rather
than inside it.
