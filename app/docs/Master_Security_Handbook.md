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