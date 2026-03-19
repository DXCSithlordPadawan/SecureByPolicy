# SecureByPolicy — Modular Security Gatekeeper

A **multi-layered, compliance-first security gate** that prevents non-compliant code and container images from reaching production.  
The system enforces NIST SP 800-53, DISA STIG, FIPS 140-3, CIS Level 2, and OWASP policies across the full Software Development Life Cycle (SDLC).

---

## Overview

```
Developer Workstation  →  Git Server (pre-receive)  →  Container Registry (Trivy)  →  Production
    [pre-commit hooks]       [Python Orchestrator]          [Quarantine/Sign]
```

| Layer | Tool | Policy |
| :--- | :--- | :--- |
| Local (Client) | pre-commit + Gitleaks + Bandit | Immediate developer feedback |
| Logic (Server) | Python Orchestrator (Podman) | Hard-stop gate on every `git push` |
| Artifact (Registry) | Trivy + Cosign | Vulnerability scan & image signing |
| Audit | SMTP Notifier | Alert Security Mailbox on Critical/High |

See the [Master Security Handbook](app/docs/Master_Security_Handbook.md) for the full operational guide.

---

## Quick Start

### Prerequisites
- Python 3.11+
- Podman 4.x (rootless)
- pre-commit 3.x

### 1. Install local pre-commit hooks
```bash
pip install pre-commit
pre-commit install --hook-type commit-msg
pre-commit install
```

### 2. Build the server-side enforcer image
```bash
podman build -t git-policy-enforcer:1.0 .
```

### 3. Deploy the pre-receive hook
```bash
cp app/scripts/pre-receive.bash /path/to/repo.git/custom_hooks/pre-receive
chmod +x /path/to/repo.git/custom_hooks/pre-receive
```

See [Pre-Live Deployment Checklist](app/docs/Pre-Live_Deployment_Checklist.md) for the full smoke-test procedure.

---

## Repository Structure

```
SecureByPolicy/
├── app/
│   ├── docs/                          # All project documentation
│   │   ├── Architecture.md            # Solution Architecture Document (SAD)
│   │   ├── Container_Registry_Scanning_Policy.md
│   │   ├── Developer_Remediation_Guide.md
│   │   ├── Draft-Email.md             # All-staff announcement template
│   │   ├── Maintenance_Guide.md       # SRE maintenance schedule
│   │   ├── Master_Security_Handbook.md
│   │   ├── Pre-Live_Deployment_Checklist.md
│   │   ├── RACI_Matrix.md
│   │   └── Security_Exemption_Form.md
│   ├── rules/
│   │   └── local_security.json        # Forbidden-pattern policy rules
│   ├── scripts/
│   │   ├── orchestrator.py            # Server-side pre-receive enforcer
│   │   ├── notifier.py                # STARTTLS SMTP alert manager
│   │   ├── pre-receive.bash           # Podman shim for Git hook
│   │   └── requirements.txt
│   └── manifest.json                  # Project metadata
├── dockerfile                         # Multi-stage FIPS-compliant image
├── .pre-commit-config.yaml            # Client-side hook configuration
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── SecureByPolicy_PRD.md              # Product Requirements Document
```

---

## Compliance Baseline

| Standard | Controls Addressed |
| :--- | :--- |
| NIST SP 800-53 | AC-3, AU-12, CM-2, SA-11, SC-8, SC-13, SI-7 |
| DISA STIG | V-222637, V-222640, V-222643, V-222645 |
| FIPS 140-3 | All hashing, signing, and TLS operations |
| CIS Level 2 | Rootless containers, dropped capabilities, read-only FS |
| OWASP | A07 (Secrets), Injection, Insecure Dependencies |

---

## Documentation Index

| Document | Purpose |
| :--- | :--- |
| [PRD](SecureByPolicy_PRD.md) | Product requirements and success metrics |
| [Master Security Handbook](app/docs/Master_Security_Handbook.md) | Comprehensive operational guide |
| [Architecture](app/docs/Architecture.md) | System design and data-flow diagrams |
| [Developer Remediation Guide](app/docs/Developer_Remediation_Guide.md) | How to fix push rejections |
| [Container Registry Policy](app/docs/Container_Registry_Scanning_Policy.md) | Registry scanning thresholds |
| [Maintenance Guide](app/docs/Maintenance_Guide.md) | SRE daily/monthly/quarterly tasks |
| [Pre-Live Checklist](app/docs/Pre-Live_Deployment_Checklist.md) | Deployment sign-off checklist |
| [RACI Matrix](app/docs/RACI_Matrix.md) | Team responsibilities |
| [Security Exemption Form](app/docs/Security_Exemption_Form.md) | SER template |
| [Gap Progress](Gap_Progress.md) | Gap analysis and progress tracking |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and coding standards.

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure procedures.
