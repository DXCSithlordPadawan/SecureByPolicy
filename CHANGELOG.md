# CHANGELOG

All notable changes to **SecureByPolicy** will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] – Initial Release

### Added
- `app/scripts/orchestrator.py` – Python-based Git pre-receive policy enforcer (NIST SI-7).
- `app/scripts/notifier.py` – STARTTLS-secured SMTP notification manager (NIST SC-8).
- `app/scripts/pre-receive.bash` – Rootless Podman shim for server-side hook deployment.
- `app/rules/local_security.json` – Forbidden-pattern rule set (OWASP A07, STIG V-222645).
- `dockerfile` – Multi-stage, FIPS-compliant container image based on Red Hat UBI8.
- `app/manifest.json` – Project metadata and compliance baseline declaration.
- `.pre-commit-config.yaml` – Client-side pre-commit hook configuration (Gitleaks, Bandit, Ruff, Hadolint, evidence stamp).
- `app/docs/Architecture.md` – Solution Architecture Document (SAD).
- `app/docs/Master_Security_Handbook.md` – Comprehensive operational handbook.
- `app/docs/Container_Registry_Scanning_Policy.md` – Registry vulnerability management policy.
- `app/docs/Developer_Remediation_Guide.md` – Developer self-service remediation guide.
- `app/docs/Maintenance_Guide.md` – SRE maintenance schedule.
- `app/docs/Pre-Live_Deployment_Checklist.md` – Pre-production deployment checklist.
- `app/docs/RACI_Matrix.md` – Governance responsibility matrix.
- `app/docs/Security_Exemption_Form.md` – Security Exception Request (SER) template.
- `app/docs/Draft-Email.md` – All-engineering announcement template.
- `SecureByPolicy_PRD.md` – Product Requirements Document.

---

## [1.1.0] – 2026-03-19

### Added
- `app/docs/Incident_Response_Plan.md` – Formal incident response procedures (NIST IR family).
- `app/docs/Metrics_Dashboard.md` – Audit-readiness reporting and metrics tracking (PRD §5).
- `app/docs/Threat_Model.md` – Risk register and threat model documentation.
- `app/docs/Golden_Image_Catalog.md` – Approved base images with SHA-256 pinning procedures and exception process.
- `app/standards/` – 13 language-specific security best practices guides (Angular, Bash, C, C++, C#, Go, Java, JavaScript, PowerShell, Python, React, Rust, TypeScript).
- `app/rules/angular_policy.json`, `bash_policy.json`, `c_policy.json`, `cpp_policy.json`, `csharp_policy.json`, `golang_policy.json`, `java_policy.json`, `javascript_policy.json`, `powershell_policy.json`, `python_policy.json`, `react_policy.json`, `rust_policy.json`, `typescript_policy.json` – Language-specific forbidden-pattern rule sets tied to OWASP, NIST SP 800-53, DISA STIG, FIPS 140-3, and CIS L2 controls.
- `.github/workflows/cosign-sign.yml` – Cosign image-signing workflow triggered post Trivy scan (NIST SI-7, STIG V-222649).
- `.github/workflows/trivy-scan.yml` – Trivy container vulnerability scanning CI workflow with hard-stop on CRITICAL/HIGH findings (NIST RA-5).
- `.github/workflows/policy-enforcement.yml` – Bandit SAST CI workflow with SARIF upload to GitHub Advanced Security.
- `CONTRIBUTING.md` – Contributor guidelines and development workflow.
- `SECURITY.md` – Security policy and vulnerability disclosure procedure.
- `Gap_Progress.md` – Living gap-analysis tracker mapping PRD requirements to implementation status.
- `.gitignore` – Excludes Python `__pycache__`, build artifacts, and other non-source files.
- `app/scripts/requirements.txt` – Python dependency manifest (`bandit`, `ruff`, `gitleaks`, etc.).
- `app/tests/test_baseline_scan_exclusions.py` – Unit tests for baseline scan path-exclusion logic (validates `app/docs/` and `app/standards/` are skipped).
- `app/scripts/test_hashing.py` – Unit tests for FIPS-compliant hashing in `orchestrator.py`.

### Changed
- `app/scripts/orchestrator.py` – Added JSON audit logging (`write_audit_log()`), language-specific diff scanning (`scan_diff_language_specific()`), `EXTENSION_TO_POLICY` map, server-side Bandit scanning, and `SKIP_EVIDENCE_CHECK`/`RULES_PATH` environment variable support.
- `app/scripts/notifier.py` – Added SMTP authentication via `SMTP_USER`/`SMTP_PASS` environment variables.
- `app/rules/local_security.json` – Updated forbidden-pattern rules to FIPS-compliant SHA-256 references (replaced insecure MD5/SHA-1 patterns, STIG V-222645).
- `README.md` – Updated with accurate file structure reflecting all new components and enforcement capabilities.
- `app/docs/Architecture.md` – Expanded with gap-analysis corrections and updated component inventory.
- `app/docs/Master_Security_Handbook.md` – Expanded with detailed operational procedures.
- `app/manifest.json` – Updated project metadata and compliance baseline declaration.

### Fixed
- `dockerfile` – Replaced placeholder base-image digests (`abcd…`, `wxyz…`) and non-existent `python-311-minimal` image with valid, digest-pinned Red Hat UBI8 references.
- `.github/workflows/cosign-sign.yml` – Normalized `IMAGE_NAME` to lowercase; added registry-configuration guard to skip signing when registry is not configured; added placeholder-digest detection step to prevent signing non-production images.
- `.github/workflows/trivy-scan.yml` – Added bypass step when `dockerfile` contains `REAL_DIGEST` placeholder to avoid scanning stub images.
- `.github/workflows/policy-enforcement.yml` – Fixed Bandit SARIF output format; updated `upload-sarif` action to v4; excluded `app/docs/` and `app/standards/` from forbidden-pattern baseline scan.
- `app/scripts/pre-receive.bash` – Minor improvements to rootless Podman invocation.

---

## [Unreleased]

### Planned
- Standalone Bandit/Ruff configuration files (`bandit.yaml`, `ruff.toml`) to replace inline `.pre-commit-config.yaml` arguments.
- Cosign/Sigstore keyless signing integration once production image digests are pinned (G-04 resolved).
