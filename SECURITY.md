# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :---: |
| 1.0.x (current) | ✅ |

---

## Reporting a Vulnerability

We take security vulnerabilities seriously. **Do not open a public GitHub issue** for security-related reports, as this could expose sensitive information before a fix is available.

### Responsible Disclosure Process

1. **Email the Security Operations team** at `security-audit@company.com` with the subject line:  
   `[SecureByPolicy] Security Vulnerability Report`
2. Include the following in your report:
   - A clear description of the vulnerability.
   - Steps to reproduce the issue.
   - The affected component(s) and version(s).
   - Your assessment of the severity (CVSS score if possible).
   - Any suggested mitigation or fix.
3. You will receive an acknowledgement within **2 business days**.
4. We aim to provide a patch or mitigation within **30 days** for High/Critical issues.
5. Once remediated, we will credit the reporter (if desired) in the CHANGELOG.

---

## Security Standards

This project enforces the following standards. Reported vulnerabilities will be assessed against these baselines:

| Standard | Scope |
| :--- | :--- |
| **NIST SP 800-53** | AC-3, AU-12, SI-7 |
| **DISA STIG** | V-222645 (Vulnerability Scanning), V-222637 (Static Analysis) |
| **FIPS 140-3** | All cryptographic operations |
| **CIS Level 2** | Container hardening |
| **OWASP** | A07 (Secrets), Injection, Insecure Dependencies |

---

## Security Exception Requests (SER)

If a known vulnerability cannot be immediately remediated, a formal **Security Exception Request** must be filed using the template in [app/docs/Security_Exemption_Form.md](app/docs/Security_Exemption_Form.md) and approved by the CISO.

---

*Last reviewed: 2026-03-19*
