# 🛡️ Master Security Handbook: DevSecOps Gatekeeper

**Version:** 1.0  
**Compliance Standards:** NIST SP 800-53, DISA STIG, FIPS 140-3, OWASP, CIS Level 2  
**Status:** FINAL/PRODUCTION  

---

## 1. Executive Summary & PRD
The **Modular Git Policy Enforcer** is a multi-layered security gate designed to prevent non-compliant code and container images from reaching production. By utilizing a "Trust but Verify" model, the system ensures developer accountability while maintaining a hardened, automated audit trail.

### 1.1 Core Objectives
* **Prevent Secret Leakage:** Automated scanning for API keys and private keys (OWASP A07).
* **Enforce Cryptographic Standards:** Block non-FIPS compliant algorithms like MD5/SHA1 (STIG V-222645).
* **Supply Chain Integrity:** Verify pre-commit scan evidence and base-image provenance (NIST SI-7).
* **Automated Oversight:** Immediate notification of high-severity violations to security teams.

---

## 2. Governance: RACI Matrix
The following matrix defines the operational responsibilities for the system.

| Task / Activity | Developer | SecOps | SRE / DevOps | CISO / Lead |
| :--- | :---: | :---: | :---: | :---: |
| **Local Pre-Commit Setup** | **R** | I | C | I |
| **Policy Definition (`rules/`)** | C | **R** | I | **A** |
| **Hook Orchestrator Maint.** | I | C | **R** | **A** |
| **Vulnerability Remediation** | **R** | I | I | **A** |
| **Approving Security Exceptions** | C | **R** | I | **A** |
| **SMTP/Audit Log Review** | I | **R** | C | I |

---

## 3. Technical Architecture
The system utilizes a multi-layered defense-in-depth strategy, moving from the developer's workstation to the central registry.

1.  **Developer Tier:** Local hooks for immediate feedback.
2.  **Logic Tier (Server-Side):** Python Orchestrator in a rootless Podman container validates every push.
3.  **Artifact Tier:** Trivy scans every image in the registry against CVSS v3.1 thresholds.
4.  **Audit Tier:** Centralized SMTP alerting for all Critical/High violations.

---

## 4. Policy Configuration: `local_security.json`
Policies are managed via a severity-based JSON structure to drive automated alerting.

```json
{
  "forbidden_patterns": [
    {
      "pattern": "BEGIN RSA PRIVATE KEY",
      "reason": "OWASP A07: Private key exposure.",
      "severity": "Critical",
      "remediation": "Remove key and rotate immediately."
    },
    {
      "pattern": "MD5",
      "reason": "STIG V-222645: Weak hashing algorithm.",
      "severity": "High",
      "remediation": "Replace with SHA256."
    }
  ]
}
```

The full rule set is maintained in `app/rules/local_security.json`.  
Policy changes require SecOps authorship and CISO accountability approval (see RACI Matrix).

---

## 5. Developer Quick-Reference: Common Violations & Fixes

### 5.1 Hardcoded Secrets (OWASP A07 – Critical)
| Trigger Pattern | Correct Approach |
| :--- | :--- |
| `BEGIN RSA PRIVATE KEY` | Move to Vault / secret mount. Rotate the key. |
| `AWS_SECRET_ACCESS_KEY=...` | Use IAM Roles or AWS Secrets Manager. |
| `password = "..."` | Inject via environment variable at runtime. |

### 5.2 Weak Cryptography (NIST FIPS 140-3 / STIG V-222645 – High)
| Forbidden | Compliant Alternative |
| :--- | :--- |
| `hashlib.md5()` | `hashlib.sha256()` |
| `hashlib.sha1()` | `hashlib.sha256()` |
| `ssl.PROTOCOL_TLSv1` | `ssl.PROTOCOL_TLS_CLIENT` + `minimum_version=TLSVersion.TLSv1_2` |

### 5.3 Missing Compliance Evidence (NIST SI-7)
- **Cause:** Developer ran `git push --no-verify`, bypassing local hooks.
- **Fix:** Run `pre-commit run --all-files`, then `git commit --amend --no-edit` to regenerate the `[COMPLIANCE-SCAN-PASSED]` stamp.

---

## 6. Hardened Containerfile Template

Use this template as the basis for all production images. It satisfies CIS Level 2 and STIG V-222640 requirements.

```dockerfile
# STAGE 1: Build Environment
FROM registry.access.redhat.com/ubi8/python-311@sha256:<PINNED_DIGEST> AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt

# STAGE 2: Production Runtime (Minimal / Clean Room)
FROM registry.access.redhat.com/ubi8/python-311-minimal@sha256:<PINNED_DIGEST>

LABEL maintainer="Security-Ops" \
      com.company.compliance="NIST-800-53-STIG" \
      com.company.fips="enabled"

# Non-root service user (CIS Level 2)
RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -m -s /sbin/nologin appuser

WORKDIR /app
COPY --from=builder --chown=appuser:appuser /build/deps /app/lib
COPY --chown=appuser:appuser . .

ENV PYTHONPATH=/app/lib

# Remove shell access and sensitive binaries (STIG V-222640)
RUN rm -rf /bin/chgrp /bin/chmod /bin/chown /usr/bin/yum*

USER appuser
ENTRYPOINT ["python3", "main.py"]
```

**Key requirements:**
- Always pin base images with `@sha256:<digest>` – never use `latest`.
- Multi-stage builds remove compilers, package managers, and shells from the final image.
- Run as a non-root user (UID/GID ≥ 10000).

---

## 7. Security Exception Request (SER) Process

When a vulnerability cannot be immediately remediated:

1. Complete the [Security Exemption Form](Security_Exemption_Form.md).
2. Submit to the `#secops-support` channel with your technical justification.
3. SecOps reviews and escalates to CISO for risk acceptance.
4. If approved, SecOps whitelists the specific commit SHA or image digest.
5. The exception expires on the date specified in the SER (maximum 30 days).
6. SRE tracks all active exceptions per the [Maintenance Guide](Maintenance_Guide.md).

---

## 8. Compliance Controls Summary

| Component | Security Control | Standard |
| :--- | :--- | :--- |
| Evidence Key (`[COMPLIANCE-SCAN-PASSED]`) | Non-Repudiation | NIST SI-7 |
| Pattern Scanning (Orchestrator) | Software Integrity | NIST SI-7 |
| Rootless Podman Container | Least Privilege | CIS Level 2 |
| STARTTLS SMTP Alerts | Cryptographic Protection in Transit | FIPS 140-3 / NIST SC-8 |
| JSON Audit Logs | Audit Record Generation | NIST AU-12 |
| SHA256 Digest Pinning | Configuration Management | NIST CM-2 |
| Trivy CVSS Gating | Vulnerability Scanning | DISA STIG V-222645 |
| Static Analysis (Bandit/Ruff) | Static Code Analysis | DISA STIG V-222637 |
| Secret Scanning (Gitleaks) | Secret Leakage Prevention | OWASP A07 |
| Cosign Image Signing | Artifact Provenance | NIST SA-11 |

---

## 9. Emergency Break-Glass Protocol

In the event of a system-wide failure of the security gate:

1. **Temporary Bypass:** Rename `pre-receive` → `pre-receive.disabled` on the Git server.
2. **Mandatory Audit:** Every push made during the break-glass window **must** be manually audited within 24 hours.
3. **Incident Report:** File an incident report and notify the CISO within 1 hour.
4. **Restoration:** Once resolved, rename the hook back and trigger a manual scan of all commits made during downtime.

---

**End of Document**  
*Version 1.0 — Status: FINAL/PRODUCTION*