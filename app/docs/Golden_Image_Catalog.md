# Golden Image Catalog: Approved Base Images

**Version:** 1.0  
**Compliance Standards:** NIST CM-2, DISA STIG V-222645, FIPS 140-3, CIS Level 2  
**Maintained By:** SecOps / SRE  
**Review Cycle:** Monthly (align with Maintenance Schedule)  
**Status:** ACTIVE

---

## Purpose

This catalog defines the **only** base images approved for use in production container builds within the SecureByPolicy environment. Any `FROM` instruction referencing an image not listed here will be rejected at the registry gate.

All entries must be:
- Pinned to an **immutable SHA256 digest** (never `latest` or a mutable tag)
- Sourced from a vendor-supported, FIPS-capable distribution
- Reviewed and re-pinned **monthly** against the vendor release feed

---

## 1. Approved Images

> **Note:** The digest values below are templates and **must** be replaced with real, verified SHA256 digests before production use. Run `skopeo inspect` (see §2) against each image to obtain the current digest. Entries marked `_PIN BEFORE PRODUCTION_` are intentionally left blank to prevent accidental use of a stale digest that may no longer be current.

### 1.1 Runtime Images

| Image Name | Registry | Tag | SHA256 Digest | FIPS-Capable | CIS Level 2 | Last Verified |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| `ubi8/python-311-minimal` | `registry.access.redhat.com` | `8.10` | _PIN BEFORE PRODUCTION — run `skopeo inspect` to obtain_ | ✅ | ✅ | —  |
| `ubi8/python-39-minimal` | `registry.access.redhat.com` | `8.10` | _PIN BEFORE PRODUCTION_ | ✅ | ✅ | — |
| `ubi8/ubi-minimal` | `registry.access.redhat.com` | `8.10` | _PIN BEFORE PRODUCTION_ | ✅ | ✅ | — |
| `ubi9/python-311-minimal` | `registry.access.redhat.com` | `9.4` | _PIN BEFORE PRODUCTION_ | ✅ | ✅ | — |

### 1.2 Build-Stage Images (Multi-Stage Builds Only)

> ⚠️ These images are permitted **only** in `AS builder` stages. They must **never** appear in a final production `FROM` instruction.

| Image Name | Registry | Tag | SHA256 Digest | Purpose | Last Verified |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ubi8/python-311` | `registry.access.redhat.com` | `8.10` | _PIN BEFORE PRODUCTION_ | Python build environment | — |
| `ubi8/go-toolset` | `registry.access.redhat.com` | `8.10` | _PIN BEFORE PRODUCTION_ | Go build environment | — |

---

## 2. How to Obtain a Verified Digest

Use `skopeo` (available on the build host) to retrieve and verify the current digest before pinning:

```bash
# Get the digest for a specific tag
skopeo inspect docker://registry.access.redhat.com/ubi8/python-311-minimal:8.10 \
  | python3 -c "import sys, json; d = json.load(sys.stdin); print(d['Digest'])"

# Verify the digest is listed in Red Hat's CDN (optional — compare with portal.access.redhat.com)
```

Once obtained, pin it in your `dockerfile`:

```dockerfile
FROM registry.access.redhat.com/ubi8/python-311-minimal@sha256:<VERIFIED_DIGEST>
```

---

## 3. Prohibited Images

The following image sources are **explicitly forbidden**:

| Prohibited Source | Reason |
| :--- | :--- |
| `docker.io/*` | Unapproved registry; no FIPS guarantee; subject to rate limits |
| `ghcr.io/*` (unapproved) | Unapproved registry; provenance cannot be guaranteed |
| `alpine:*` (unvetted) | No FIPS-validated crypto modules; not in approved catalog |
| Any `*:latest` tag | Mutable — breaks reproducibility and immutability requirements |
| Any image with no SHA256 pin | Cannot ensure supply-chain integrity (NIST SI-7) |
| Images older than 90 days without re-verification | May contain unpatched CVEs (STIG V-222645) |

---

## 4. Exception Process

If a project requires an image not listed in this catalog:

1. File a **Security Exception Request (SER)** via the [Security Exemption Form](Security_Exemption_Form.md).
2. Include: image name, registry URL, business justification, FIPS compliance evidence, and Trivy scan output.
3. SecOps and CISO must approve before the image is added to this catalog.
4. Exception images are added to Section 1 upon approval with a clearly marked **Approved By** field.

---

## 5. Compliance Mapping

| Control | Standard | Implementation |
| :--- | :--- | :--- |
| Configuration Management | NIST CM-2 | Images pinned to immutable SHA256 digests |
| Software Integrity | NIST SI-7 | Digest verification via `skopeo` before every build |
| Vulnerability Scanning | DISA STIG V-222645 | All catalog images scanned monthly with Trivy |
| FIPS-Validated Crypto | FIPS 140-3 | All approved images are Red Hat UBI FIPS-capable |
| Least Privilege / Hardening | CIS Level 2 | Minimal images (no shell, no package manager in runtime) |
| Container Provenance | NIST SA-11 | Cosign-signed images promoted to `stable` library |

---

## 6. Catalog Maintenance Procedure

| Frequency | Action | Owner |
| :--- | :--- | :--- |
| **Monthly** | Re-run `skopeo inspect` for each image; update SHA256 entries if changed | SRE |
| **Monthly** | Run Trivy against each catalog image; fail any with unpatched CRITICAL CVEs | SecOps |
| **On vendor release** | Evaluate new UBI minor/patch versions; promote to catalog after passing scan | SecOps |
| **On CVE disclosure** | Emergency re-scan; replace digest and rebuild all consuming images if affected | SecOps / SRE |

---

**End of Document**  
*Version 1.0 — Status: ACTIVE — Review Monthly*
