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

### Server-Side Enforcement Pipeline

Each pushed commit passes through four sequential gates:

1. **Evidence Check** — Verifies the developer ran local pre-commit hooks (NIST SI-7).
2. **Baseline Forbidden-Pattern Scan** — Scans added source-code lines against cross-language forbidden patterns (OWASP A07, STIG V-222645).
3. **Language-Specific Policy Scan** — Applies a dedicated policy file per file extension (e.g. `python_policy.json`, `java_policy.json`) to catch language-idiomatic vulnerabilities (NIST SA-11, OWASP Top 10).
4. **Bandit Static Analysis** — Runs Bandit on every Python file in the commit for deeper SAST coverage (DISA STIG V-222637).

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
│   │   ├── Golden_Image_Catalog.md    # Approved base-image registry (NIST CM-2)
│   │   ├── Incident_Response_Plan.md  # Security gate incident response (NIST IR-4)
│   │   ├── Maintenance_Guide.md       # SRE maintenance schedule
│   │   ├── Master_Security_Handbook.md
│   │   ├── Metrics_Dashboard.md       # Security KPI dashboard (NIST AU-12)
│   │   ├── Pre-Live_Deployment_Checklist.md
│   │   ├── RACI_Matrix.md
│   │   ├── Security_Exemption_Form.md
│   │   └── Threat_Model.md            # STRIDE threat model / risk register (NIST SA-11)
│   ├── rules/
│   │   ├── local_security.json        # Cross-language baseline forbidden-pattern rules
│   │   ├── angular_policy.json        # Angular-specific security policy
│   │   ├── bash_policy.json           # Bash/Shell-specific security policy
│   │   ├── c_policy.json              # C-specific security policy
│   │   ├── cpp_policy.json            # C++-specific security policy
│   │   ├── csharp_policy.json         # C#-specific security policy
│   │   ├── golang_policy.json         # Go-specific security policy
│   │   ├── java_policy.json           # Java-specific security policy
│   │   ├── javascript_policy.json     # JavaScript-specific security policy
│   │   ├── powershell_policy.json     # PowerShell-specific security policy
│   │   ├── python_policy.json         # Python-specific security policy
│   │   ├── react_policy.json          # React/JSX-specific security policy
│   │   ├── rust_policy.json           # Rust-specific security policy
│   │   └── typescript_policy.json     # TypeScript-specific security policy
│   ├── scripts/
│   │   ├── orchestrator.py            # Server-side pre-receive enforcer
│   │   ├── notifier.py                # STARTTLS SMTP alert manager
│   │   ├── pre-receive.bash           # Podman shim for Git hook
│   │   ├── requirements.txt
│   │   └── test_hashing.py            # FIPS 140-3 hashing compliance tests
│   ├── skills/                        # Claude AI compliance checker skills
│   │   ├── README.md                  # Skills index and usage guide
│   │   ├── angular_skill.md           # Angular compliance checker skill
│   │   ├── bash_skill.md              # Bash/Shell compliance checker skill
│   │   ├── c_skill.md                 # C compliance checker skill
│   │   ├── cpp_skill.md               # C++ compliance checker skill
│   │   ├── csharp_skill.md            # C# compliance checker skill
│   │   ├── golang_skill.md            # Go compliance checker skill
│   │   ├── java_skill.md              # Java compliance checker skill
│   │   ├── javascript_skill.md        # JavaScript compliance checker skill
│   │   ├── powershell_skill.md        # PowerShell compliance checker skill
│   │   ├── python_skill.md            # Python compliance checker skill
│   │   ├── react_skill.md             # React/JSX compliance checker skill
│   │   ├── rust_skill.md              # Rust compliance checker skill
│   │   └── typescript_skill.md        # TypeScript compliance checker skill
│   ├── standards/                     # Language security best-practices guides
│   │   ├── Angular_Security_Best_Practices_Guide.md
│   │   ├── Bash_Security_Best_Practices_Guide.md
│   │   ├── C_Security_Best_Practices_Guide.md
│   │   ├── CPP_Security_Best_Practices_Guide.md
│   │   ├── CSharp_Security_Best_Practices_Guide.md
│   │   ├── Golang_Security_Best_Practices_Guide.md
│   │   ├── Java_Security_Best_Practices_Guide.md
│   │   ├── JavaScript_Security_Best_Practices_Guide.md
│   │   ├── PowerShell_Security_Best_Practices_Guide.md
│   │   ├── Python_Security_Best_Practices_Guide.md
│   │   ├── React_Security_Best_Practices_Guide.md
│   │   ├── Rust_Security_Best_Practices_Guide.md
│   │   └── TypeScript_Security_Best_Practices_Guide.md
│   ├── tests/
│   │   └── test_baseline_scan_exclusions.py  # Unit tests for scan path-exclusion logic
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
| [Golden Image Catalog](app/docs/Golden_Image_Catalog.md) | Approved container base images (NIST CM-2) |
| [Incident Response Plan](app/docs/Incident_Response_Plan.md) | Security gate incident response procedures |
| [Metrics Dashboard](app/docs/Metrics_Dashboard.md) | Security KPIs and audit-readiness reporting |
| [Threat Model](app/docs/Threat_Model.md) | STRIDE threat model and risk register |
| [Gap Progress](Gap_Progress.md) | Gap analysis and progress tracking |
| [Claude Skills](app/skills/README.md) | AI compliance checker skills — one per supported language |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and coding standards.

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure procedures.
