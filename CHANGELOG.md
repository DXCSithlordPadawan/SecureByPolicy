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

## [Unreleased]

### Planned
- Cosign image-signing integration post Trivy scan pass.
- Bandit/Ruff configuration files (`bandit.yaml`, `ruff.toml`).
- Metrics dashboard for audit-readiness reporting (PRD §5).
- Incident Response Plan document.
- Threat Model / Risk Register document.
