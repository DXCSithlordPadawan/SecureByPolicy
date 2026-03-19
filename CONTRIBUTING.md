# Contributing to SecureByPolicy

Thank you for your interest in contributing to the **Modular Security Gatekeeper** project.  
This project enforces NIST SP 800-53, DISA STIG, FIPS 140-3, CIS Level 2, and OWASP policies across the SDLC.  
All contributions must comply with the security standards defined in the [Master Security Handbook](app/docs/Master_Security_Handbook.md).

---

## Getting Started

### Prerequisites

| Tool | Purpose | Minimum Version |
| :--- | :--- | :--- |
| Python | Script runtime | 3.11 |
| Podman | Rootless container runtime | 4.x |
| pre-commit | Local hook management | 3.x |
| Trivy | Container vulnerability scanning | 0.50+ |

### Local Setup

1. **Clone the repository** and navigate to the project root.
2. **Install pre-commit hooks:**
   ```bash
   pip install pre-commit
   pre-commit install --hook-type commit-msg
   pre-commit install
   ```
3. **Verify hooks are active:**
   ```bash
   pre-commit run --all-files
   ```
   All hooks must pass before you can commit. A successful run stamps  
   `[COMPLIANCE-SCAN-PASSED]` into your commit message automatically.

---

## Contribution Workflow

1. **Create a feature branch** from `main` using the naming convention:  
   `feature/<short-description>` or `fix/<short-description>`
2. **Make your changes** following the coding standards below.
3. **Commit** – local pre-commit hooks will scan and stamp your commit.
4. **Open a Pull Request** against `main`. The PR description must include:
   - What was changed and why.
   - Which PRD requirement or gap item is addressed.
   - Any compliance controls affected (NIST control IDs, STIG IDs, etc.).

---

## Coding Standards

- **Python:** Follow PEP 8. All code is linted by Ruff and analysed by Bandit.
- **Secrets:** Never commit credentials, keys, or passwords. Use environment variables or a secrets manager.
- **Cryptography:** Only FIPS 140-3 approved algorithms are permitted (SHA-256+, AES-256, TLS 1.2+).
- **Containerfiles:** Must use approved Golden Image base images with pinned `@sha256` digests.
- **Policy rules (`local_security.json`):** Changes require SecOps review and CISO accountability sign-off (see [RACI Matrix](app/docs/RACI_Matrix.md)).

---

## Reporting Security Vulnerabilities

Please **do not** open a public issue for security vulnerabilities.  
Follow the process in [SECURITY.md](SECURITY.md).

---

## Code of Conduct

All contributors are expected to behave professionally and respectfully.  
Harassment or discrimination of any kind will not be tolerated.
