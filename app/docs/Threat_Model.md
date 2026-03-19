# Threat Model: Modular Git Policy Enforcer

**Version:** 1.0  
**Compliance Standards:** NIST SA-11, NIST RA-3, OWASP Threat Modeling  
**Methodology:** STRIDE  
**Maintained By:** SecOps  
**Review Cycle:** Quarterly, and on any architectural change  
**Status:** ACTIVE

---

## 1. System Overview

The **Modular Git Policy Enforcer** is a three-tier security gate:

```
[Developer Workstation]
        │  git push
        ▼
[Git Server — pre-receive hook]
   └─► [Podman Container: orchestrator.py]
           ├── check_evidence()    — validates [COMPLIANCE-SCAN-PASSED] stamp
           ├── scan_diff()         — pattern-match against local_security.json
           └── NotificationManager — SMTP alert to Security Audit Mailbox
        │  ALLOW / REJECT
        ▼
[Container Registry]
   └─► [Trivy Scan]
           ├── CVSS v3.1 threshold gate
           └── Cosign signing on pass
```

**Assets to protect:**

| Asset | Confidentiality | Integrity | Availability |
| :--- | :---: | :---: | :---: |
| Source code on `main` / `release` branches | Medium | **High** | Medium |
| Production container images in `stable` library | Low | **Critical** | **High** |
| Security rules (`local_security.json`) | Low | **Critical** | Medium |
| SMTP credentials (`SMTP_PASS` env var) | **Critical** | High | Low |
| Audit log / SIEM feed | Medium | **High** | **High** |
| Pre-receive hook binary | Low | **Critical** | **High** |

---

## 2. Trust Boundaries

| Boundary | Crossing Point | Trust Level |
| :--- | :--- | :--- |
| Developer workstation → Git server | `git push` over SSH/HTTPS | **Untrusted input** |
| Git server → Podman container | stdin pipe + mounted rule volume | **Privileged — must be verified** |
| Container → SMTP server | TCP/STARTTLS | **Semi-trusted network** |
| Container registry → CI/CD pipeline | Webhook | **Trusted with signature verification** |
| Rule file volume mount (`/app/rules:ro`) | Filesystem | **Trusted — read-only mount** |

---

## 3. STRIDE Threat Analysis

### 3.1 Spoofing

| Threat ID | Threat | Component | Likelihood | Impact | Mitigation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| T-S1 | Developer forges `[COMPLIANCE-SCAN-PASSED]` stamp in commit message manually | `orchestrator.py: check_evidence()` | **High** | High | Evidence stamp is a necessary but not sufficient control; pair with server-side re-scan (Bandit) to validate the diff directly — see Gap G-10 |
| T-S2 | Attacker spoofs Git server identity to intercept push | SSH / HTTPS layer | Low | Critical | Enforce SSH host-key verification and HTTPS certificate pinning on developer workstations |
| T-S3 | Malicious image tagged to mimic an approved golden image digest | Container registry | Low | Critical | Cosign signature verification; immutable SHA256 digest pinning in `dockerfile` (not just tag) |

### 3.2 Tampering

| Threat ID | Threat | Component | Likelihood | Impact | Mitigation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| T-T1 | Attacker modifies `local_security.json` to weaken or remove rules | Rule file on Git server | Medium | Critical | Mount rules volume as **read-only** (`-v /etc/git-policy/rules:/app/rules:ro`); rules file changes require SecOps + CISO approval (RACI); git blame trail |
| T-T2 | Attacker replaces the `pre-receive` hook binary with a no-op | Git server filesystem | Low | Critical | File integrity monitoring (FIM) on `/path/to/hooks/pre-receive`; hook file owned by `git` service account, not writable by developers |
| T-T3 | Supply-chain attack on the `git-policy-enforcer` container image | Container registry | Low | Critical | Pin container image to SHA256 digest in `pre-receive.bash` (Gap G-12); Cosign signature verification before container launch |
| T-T4 | Attacker tampers with audit logs | Log storage / SIEM | Medium | High | Write audit logs to an append-only SIEM endpoint; deny log-delete permissions to the container service account |

### 3.3 Repudiation

| Threat ID | Threat | Component | Likelihood | Impact | Mitigation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| T-R1 | Developer denies having pushed non-compliant code | Audit log | Medium | High | JSON audit log records `{timestamp, user, repo, sha, violation, action}` — immutable SIEM storage; `[COMPLIANCE-SCAN-PASSED]` stamp tied to commit SHA |
| T-R2 | Admin denies authorizing break-glass bypass | Approval workflow | Low | High | Written approval required (email with timestamp); break-glass log archived to SIEM (see Incident Response Plan §4) |

### 3.4 Information Disclosure

| Threat ID | Threat | Component | Likelihood | Impact | Mitigation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| T-I1 | `SMTP_PASS` environment variable leaked via container inspection | Podman environment | Medium | Critical | Never hardcode credentials; inject via secrets manager or Podman secrets; `--security-opt no-new-privileges` prevents privilege escalation to read env |
| T-I2 | Rejection message reveals internal path / rule structure to attacker | Terminal output from `orchestrator.py` | Low | Medium | Rejection messages show the violation type and remediation but not the full rule-file path or internal logic; review message templates for information leakage |
| T-I3 | Audit log forwarded unencrypted to SIEM | SMTP / log transport | Medium | High | Use STARTTLS for SMTP (already implemented in `notifier.py`); TLS for SIEM log forwarding |

### 3.5 Denial of Service

| Threat ID | Threat | Component | Likelihood | Impact | Mitigation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| T-D1 | Attacker submits a push with an extremely large diff to exhaust container memory/CPU | `orchestrator.py: scan_diff()` | Medium | High | Enforce diff size limit before scanning (e.g., reject diffs > 50 MB); set container memory/CPU limits in `pre-receive.bash` |
| T-D2 | Trivy CVE database becomes unavailable — scanner cannot complete | Trivy / CI pipeline | Medium | High | Cache Trivy DB locally (daily `trivy image --download-db-only`); configure a pipeline step that **fails the build** if the cached DB is older than 48 hours — never allow unscanned images to be promoted; alert SecOps so the DB can be refreshed |
| T-D3 | SMTP server unreachable — violations not alerted | `notifier.py` | Medium | Medium | `notifier.py` already has `try/except`; add dead-letter queue or secondary alerting channel (e.g., Slack webhook) |

### 3.6 Elevation of Privilege

| Threat ID | Threat | Component | Likelihood | Impact | Mitigation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| T-E1 | Container process escapes to host via kernel vulnerability | Podman container runtime | Low | Critical | Rootless Podman (`--cap-drop=all`, `--read-only`, `--security-opt no-new-privileges`); host kernel kept patched |
| T-E2 | Malicious Python dependency in `requirements.txt` executes arbitrary code during build | Build stage | Low | Critical | Pin all dependency versions in `requirements.txt`; run Trivy + pip-audit on the requirements file in CI before building |
| T-E3 | Developer with `git` server access modifies hook directly | Git server OS account | Low | Critical | Separate `git` service account with minimal OS permissions; audit all logins to the git server host |

---

## 4. Risk Summary & Priority Order

| ID | Threat | Risk Level | Status |
| :--- | :--- | :---: | :--- |
| T-S1 | Evidence stamp forged manually | **High** | ⚠️ Partial — Gap G-10 (server-side Bandit) needed |
| T-T1 | Rule file tampered | **High** | ✅ Read-only mount in place |
| T-T3 | Container image supply-chain attack | **High** | ⚠️ Partial — Gap G-12 (digest pinning) needed |
| T-I1 | SMTP credentials leaked | **High** | ✅ Env-var pattern in place; Gap G-02 (SMTP auth uncommented) |
| T-D1 | Oversized diff DoS | **High** | ❌ No diff size limit implemented |
| T-T2 | Hook binary replaced | **Medium** | ❌ No FIM configured |
| T-T4 | Audit log tampered | **Medium** | ⚠️ Gap G-03 (JSON log) needed |
| T-R1 | Push repudiation | **Medium** | ⚠️ Gap G-03 (JSON log) needed |
| T-D2 | Trivy DB unavailable | **Medium** | ⚠️ Daily DB sync in Maintenance Guide — not automated in CI |
| T-I3 | Unencrypted log transport | **Medium** | ✅ STARTTLS in `notifier.py` |
| T-E1 | Container escape | **Low** | ✅ Rootless Podman + dropped capabilities |
| T-S2 | Git server identity spoofing | **Low** | ✅ SSH host-key best practices |

---

## 5. Recommended Mitigations (Not Yet Implemented)

| Mitigation | Addresses | Priority |
| :--- | :--- | :--- |
| Server-side Bandit scan in `orchestrator.py` | T-S1 | P1 — Gap G-10 |
| Pin container image in `pre-receive.bash` to SHA256 digest | T-T3 | P2 — Gap G-12 |
| Diff size limit in `orchestrator.py` (reject > 50 MB) | T-D1 | P2 |
| File Integrity Monitoring on hook binary | T-T2 | P2 |
| JSON structured audit log in `orchestrator.py` | T-T4, T-R1 | P1 — Gap G-03 |
| Wire `notifier.py` into `orchestrator.py` | T-D3 | P1 — Gap G-01 |
| Enable SMTP authentication in `notifier.py` | T-I1 | P1 — Gap G-02 |

---

## 6. Compliance Mapping

| Control | Standard | Threat(s) Addressed |
| :--- | :--- | :--- |
| Threat / Risk Assessment | NIST RA-3 | All STRIDE categories above |
| Developer Security Testing | NIST SA-11 | T-S1, T-T1, T-T2 |
| Least Privilege | NIST AC-6 | T-E1, T-E3 |
| Audit Record Generation | NIST AU-12 | T-R1, T-R2, T-T4 |
| Software Integrity | NIST SI-7 | T-S1, T-T3, T-T2 |
| Cryptographic Protection | NIST SC-13 / FIPS 140-3 | T-I3 |
| Vulnerability Scanning | DISA STIG V-222645 | T-T3, T-E2 |

---

**End of Document**  
*Version 1.0 — Status: ACTIVE — Review Quarterly*
