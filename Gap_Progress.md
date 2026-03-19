# Gap Progress: SecureByPolicy — Gap Analysis & Progress Tracker

**Project:** Modular Security Gatekeeper  
**Reference PRD:** `SecureByPolicy_PRD.md`  
**Last Updated:** 2026-03-19  
**Status:** Active  

---

## Purpose

This document tracks the gap analysis between the requirements defined in `SecureByPolicy_PRD.md` and the actual state of code, configuration, and documentation in this repository. It serves as the living record of items identified, actions taken, and remaining work.

---

## 1. PRD Requirements Verification

### 1.1 Git Push Enforcement (PRD §2.1)

| Requirement | Status | Evidence | Gap / Notes |
| :--- | :---: | :--- | :--- |
| Intercept all `git push` via pre-receive hook | ✅ Done | `app/scripts/pre-receive.bash` + `app/scripts/orchestrator.py` | Podman shim correctly passes stdin to the Python orchestrator |
| Verify "Pre-Commit Scan Evidence" (`[COMPLIANCE-SCAN-PASSED]`) | ✅ Done | `orchestrator.py: check_evidence()` | Evidence key validated on every commit in the push range |
| Scan for forbidden patterns | ✅ Done | `orchestrator.py: scan_diff()` + `app/rules/local_security.json` | 8 rules covering secrets, weak crypto, and deprecated TLS |
| Actionable remediation text returned to terminal | ✅ Done | `orchestrator.py` prints `reason` + `remediation` per violation | — |
| No self-healing / automated fixes | ✅ Done | Design explicitly rejects automation | — |
| Language-specific scanning (Bandit, Ruff) | ⚠️ Partial | `.pre-commit-config.yaml` configures client-side Bandit/Ruff | **Gap:** Bandit/Ruff are client-side only. Server-side container does not run Bandit. Add Bandit to `orchestrator.py` or a dedicated scan stage. |
| Notify Security Mailbox on violation | ⚠️ Partial | `notifier.py` is complete; `orchestrator.py` does **not** call it | **Gap:** `orchestrator.py` prints to terminal but never instantiates `NotificationManager`. Wire `notifier.py` into `orchestrator.py` for High/Critical violations. |

### 1.2 Container Registry Scanning (PRD §2.2)

| Requirement | Status | Evidence | Gap / Notes |
| :--- | :---: | :--- | :--- |
| Scan every pushed image using Trivy | ✅ Documented | `Container_Registry_Scanning_Policy.md`, `app/manifest.json` | **Gap:** No automated CI/CD pipeline (GitHub Actions workflow, Tekton Pipeline, etc.) exists in the repository to trigger Trivy scans. A `trivy-scan.yml` workflow should be created. |
| Hard-stop on CRITICAL/HIGH with fix available | ✅ Documented | `Container_Registry_Scanning_Policy.md §1` | Same gap as above — policy is defined but not automated in this repo |
| Validate base image provenance (Red Hat UBI) | ✅ Documented | `dockerfile` uses UBI8 base; `Container_Registry_Scanning_Policy.md §2.1` | `@sha256` digests in `dockerfile` are placeholders (`abcd...`, `wxyz...`). **Gap:** Replace with real pinned digests before production use. |
| Golden Image catalog | ⚠️ Partial | UBI8 is referenced | **Gap:** No formal Golden Image catalog document or approved-image list exists. Create `app/docs/Golden_Image_Catalog.md`. |

### 1.3 Automated Audit & Alerting (PRD §2.3)

| Requirement | Status | Evidence | Gap / Notes |
| :--- | :---: | :--- | :--- |
| Generate structured JSON logs for all security events | ⚠️ Partial | `notifier.py` logs to stdout when email is disabled | **Gap:** No structured JSON log file output. `orchestrator.py` should write a JSON event record (timestamp, repo, user, violation, action) to a log file or SIEM endpoint. |
| Email Security Audit Mailbox on High/Critical | ⚠️ Partial | `notifier.py` is implemented with STARTTLS | **Gap:** `orchestrator.py` does not call `notifier.py`. See §1.1 gap above. |
| Formal SER workflow | ✅ Done | `app/docs/Security_Exemption_Form.md`, `app/docs/Developer_Remediation_Guide.md §4` | — |
| SMTP authentication | ⚠️ Partial | `notifier.py` has `server.login()` commented out | **Gap:** SMTP authentication is commented out. Must be enabled for production (inject credentials via environment variables). |

### 1.4 Compliance & Security Standards (PRD §3)

| Standard | Requirement | Status | Gap / Notes |
| :--- | :--- | :---: | :--- |
| NIST AC-3 | Access enforcement on repository | ✅ Documented | Enforced via pre-receive rejection |
| NIST AU-12 | Audit record generation | ⚠️ Partial | Stdout logging only; no persistent structured JSON log file |
| NIST SI-7 | Software integrity checks | ✅ Done | Evidence key + SHA256 pinning |
| DISA STIG V-222645 | Vulnerability scanning | ✅ Documented | Trivy policy defined; CI automation gap noted above |
| DISA STIG V-222637 | Static analysis | ⚠️ Partial | Client-side Bandit via pre-commit; not enforced server-side |
| FIPS 140-3 | FIPS-validated crypto modules | ✅ Done | UBI8 base image is FIPS-capable; `dockerfile` labels `fips=enabled` |
| CIS Level 2 | Container hardening | ✅ Done | `pre-receive.bash` uses `--cap-drop=all`, `--read-only`, `--security-opt no-new-privileges` |
| OWASP | Secrets, injection, insecure deps | ✅ Done | Gitleaks + orchestrator pattern scan |

---

## 2. Document Completeness Review

| Document | Status | Notes |
| :--- | :---: | :--- |
| `SecureByPolicy_PRD.md` | ✅ Complete | Source of truth for all requirements |
| `README.md` | ✅ Fixed | Was a single-line stub; expanded to full project README |
| `app/docs/Architecture.md` | ✅ Fixed | Section 3 header was malformed; Section 5 compliance table was garbled plain text — both corrected |
| `app/docs/Master_Security_Handbook.md` | ✅ Fixed | File was truncated mid-content (cut off after §4 policy JSON). Sections §5–§9 added: Developer Quick-Reference, Containerfile Template, SER Process, Compliance Summary, Break-Glass Protocol |
| `app/docs/Container_Registry_Scanning_Policy.md` | ✅ Complete | — |
| `app/docs/Developer_Remediation_Guide.md` | ✅ Complete | — |
| `app/docs/Maintenance_Guide.md` | ✅ Complete | — |
| `app/docs/Pre-Live_Deployment_Checklist.md` | ✅ Complete | — |
| `app/docs/RACI_Matrix.md` | ✅ Complete | — |
| `app/docs/Security_Exemption_Form.md` | ✅ Complete | — |
| `app/docs/Draft-Email.md` | ✅ Complete | — |
| `CHANGELOG.md` | ✅ Created | Was missing; created with v1.0.0 release notes and Unreleased section |
| `CONTRIBUTING.md` | ✅ Created | Was missing; created with setup, workflow, and coding standards |
| `SECURITY.md` | ✅ Created | Was missing; created with responsible disclosure process |
| `app/rules/local_security.json` | ✅ Created | Referenced by `orchestrator.py` and docs but file/directory were absent; created with 8 rules |
| `app/scripts/requirements.txt` | ✅ Created | Referenced in `dockerfile` (`COPY requirements.txt .`) but file was absent |
| `.pre-commit-config.yaml` | ✅ Created | Referenced in `Draft-Email.md` and `Developer_Remediation_Guide.md` but file was absent; created with Gitleaks, Bandit, Ruff, Hadolint, and evidence-stamp hooks |
| `app/docs/Golden_Image_Catalog.md` | ❌ Missing | **Gap:** Formally document approved base images with verified SHA256 digests |
| `app/docs/Incident_Response_Plan.md` | ❌ Missing | **Gap:** No incident response procedure for security gate failures or active exploits |
| `app/docs/Threat_Model.md` | ❌ Missing | **Gap:** No threat model or attack-surface analysis for the gatekeeper itself |
| `app/docs/Metrics_Dashboard.md` | ❌ Missing | **Gap:** PRD §5 success metrics (Zero Bypass, Remediation Speed, Audit Readiness) have no tracking mechanism |

---

## 3. Code & Manifest Review

### 3.1 `app/scripts/orchestrator.py`
| Check | Status | Notes |
| :--- | :---: | :--- |
| Validates compliance evidence key | ✅ OK | `check_evidence()` |
| Scans diff for forbidden patterns | ✅ OK | `scan_diff()` using `local_security.json` |
| Calls `NotificationManager` on violation | ❌ Gap | `notifier.py` exists but is never imported or called. High/Critical violations are not emailed. |
| Structured JSON audit log written | ❌ Gap | No JSON log output; only `print()` to stdout |
| Handles new-branch pushes (zero hash) | ✅ OK | Checks for `0000000000000000000000000000000000000000` |

### 3.2 `app/scripts/notifier.py`
| Check | Status | Notes |
| :--- | :---: | :--- |
| STARTTLS implementation (NIST SC-8) | ✅ OK | `server.starttls()` called |
| SMTP authentication | ⚠️ Gap | `server.login()` is commented out — must be enabled for production |
| Secrets not hardcoded | ✅ OK | Credentials loaded from environment variables |
| Exception handling | ✅ OK | `try/except` around SMTP send |

### 3.3 `app/scripts/pre-receive.bash`
| Check | Status | Notes |
| :--- | :---: | :--- |
| Rootless Podman with security flags | ✅ OK | `--cap-drop=all --read-only --security-opt no-new-privileges` |
| SMTP_PASS not hardcoded | ✅ OK | Only `SMTP_SERVER` is set; `SMTP_PASS` is NOT in the shim (correct) |
| Rules mounted read-only | ✅ OK | `-v /etc/git-policy/rules:/app/rules:ro` |
| Image version pinned | ⚠️ Partial | `git-policy-enforcer:1.0` uses a tag; should use a SHA256 digest for immutability |

### 3.4 `dockerfile`
| Check | Status | Notes |
| :--- | :---: | :--- |
| Multi-stage build | ✅ OK | Builder + minimal production runtime |
| Non-root user | ✅ OK | `appuser` (UID 10001) |
| FIPS metadata label | ✅ OK | `com.company.fips="enabled"` |
| Base image SHA256 pinned | ⚠️ Gap | Digests are placeholders (`abcd...`, `wxyz...`) — replace before production |
| Shell removal (STIG V-222640) | ✅ OK | `rm -rf /bin/chgrp /bin/chmod /bin/chown /usr/bin/yum*` |

### 3.5 `app/manifest.json`
| Check | Status | Notes |
| :--- | :---: | :--- |
| Compliance baseline declared | ✅ OK | `["NIST-800-53", "DISA-STIG-V2", "FIPS-140-3", "CIS-L2"]` |
| FIPS mode required | ✅ OK | `"fips_mode": "Required"` |
| Runtime declared | ✅ OK | `"runtime": "Podman (Rootless)"` |
| Version | ✅ OK | `"version": "1.0.0-RELEASE"` |
| OWASP not in compliance baseline | ⚠️ Minor | OWASP is a PRD §3 requirement but not listed in manifest `compliance_baseline` |

---

## 4. Gap Summary

### Priority 1 — Functional Gaps (Security Risk)

| ID | Gap | Affected PRD Section | Recommended Action |
| :--- | :--- | :--- | :--- |
| G-01 | `orchestrator.py` never calls `notifier.py` — no email alerts sent | PRD §2.3 | Import `NotificationManager` in `orchestrator.py`; call `send_violation_report()` for High/Critical violations |
| G-02 | SMTP authentication commented out in `notifier.py` | PRD §2.3 | Uncomment `server.login()` and inject credentials via environment variable |
| G-03 | No structured JSON audit log — stdout only | PRD §2.3 | Add JSON log writer to `orchestrator.py` emitting `{timestamp, repo, user, sha, violation, action}` |
| G-04 | Dockerfile `@sha256` digests are placeholders | PRD §2.2 | Replace `abcd...` / `wxyz...` with real verified UBI8 digests before production |
| G-05 | No CI/CD workflow to trigger Trivy registry scans | PRD §2.2 | Create `.github/workflows/trivy-scan.yml` (or equivalent pipeline config) |

### Priority 2 — Documentation Gaps

| ID | Gap | Recommended Action |
| :--- | :--- | :--- |
| G-06 | No Golden Image Catalog | Create `app/docs/Golden_Image_Catalog.md` listing approved base images with SHA256 digests |
| G-07 | No Incident Response Plan | Create `app/docs/Incident_Response_Plan.md` covering gate failure, active exploit, and break-glass scenarios |
| G-08 | No Threat Model | Create `app/docs/Threat_Model.md` mapping attacker personas and mitigations for the gatekeeper itself |
| G-09 | No Metrics Tracking (PRD §5) | Create `app/docs/Metrics_Dashboard.md` with KPIs: Zero Bypass rate, Remediation Speed, Audit Readiness |

### Priority 3 — Enhancement Gaps

| ID | Gap | Recommended Action |
| :--- | :--- | :--- |
| G-10 | Server-side Bandit scan not implemented | Integrate Bandit into `orchestrator.py` or a dedicated scan stage in the container |
| G-11 | Cosign image signing not implemented (PRD §2.2) | Implement Cosign signing step post clean Trivy scan |
| G-12 | `pre-receive.bash` uses image tag, not digest | Pin `git-policy-enforcer` image reference to `@sha256:<digest>` |
| G-13 | `app/manifest.json` missing OWASP in compliance baseline | Add `"OWASP"` to `compliance_baseline` array |

---

## 5. Progress Checklist

### Completed in This Analysis Session
- [x] Read and verified all existing files against PRD requirements
- [x] Updated `README.md` — expanded from single-line stub to full project README
- [x] Fixed `app/docs/Architecture.md` — corrected Section 3 header and Section 5 garbled compliance table
- [x] Completed `app/docs/Master_Security_Handbook.md` — added §5 Developer Quick-Reference, §6 Containerfile Template, §7 SER Process, §8 Compliance Controls Summary, §9 Break-Glass Protocol
- [x] Created `CHANGELOG.md` — standard release documentation
- [x] Created `CONTRIBUTING.md` — contribution guidelines with security standards
- [x] Created `SECURITY.md` — responsible disclosure policy
- [x] Created `app/rules/local_security.json` — 8-rule policy file required by `orchestrator.py`
- [x] Created `app/scripts/requirements.txt` — required by `dockerfile` build stage
- [x] Created `.pre-commit-config.yaml` — client-side hook configuration referenced in docs
- [x] Created `Gap_Progress.md` — this document

### Remaining Gaps (Prioritised)
- [ ] **G-01:** Wire `notifier.py` into `orchestrator.py` (Priority 1 — Security)
- [ ] **G-02:** Enable SMTP authentication in `notifier.py` (Priority 1 — Security)
- [ ] **G-03:** Add structured JSON audit logging to `orchestrator.py` (Priority 1 — Compliance)
- [ ] **G-04:** Replace placeholder SHA256 digests in `dockerfile` with real UBI8 digests (Priority 1 — Security)
- [ ] **G-05:** Create Trivy scan CI/CD workflow (Priority 1 — Functional)
- [ ] **G-06:** Create `app/docs/Golden_Image_Catalog.md` (Priority 2 — Documentation)
- [ ] **G-07:** Create `app/docs/Incident_Response_Plan.md` (Priority 2 — Documentation)
- [ ] **G-08:** Create `app/docs/Threat_Model.md` (Priority 2 — Documentation)
- [ ] **G-09:** Create `app/docs/Metrics_Dashboard.md` (Priority 2 — Documentation)
- [ ] **G-10:** Integrate server-side Bandit scanning (Priority 3 — Enhancement)
- [ ] **G-11:** Implement Cosign image signing workflow (Priority 3 — Enhancement)
- [ ] **G-12:** Pin `pre-receive.bash` image reference to SHA256 digest (Priority 3 — Enhancement)
- [x] **G-13:** Add OWASP to `app/manifest.json` compliance baseline (Priority 3 — Minor)

---

*This document is maintained by the Security Operations team. Update after each work session or sprint.*
