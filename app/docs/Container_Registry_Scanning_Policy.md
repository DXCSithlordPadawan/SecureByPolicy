# Container Registry Scanning Policy: Vulnerability Management

This policy defines the mandatory security gates for all containerized artifacts. To ensure compliance with **DISA STIG V-222645** and **NIST SP 800-53**, the registry acts as a final "Hard-Stop" before images are permitted for deployment.

---

## 1. Automated Rejection Thresholds
Every image push triggers an automated scan (Trivy/Grype). Rejection logic is driven by **CVSS v3.1** scores:

| Severity | CVSS Score Range | Policy Action | Remediation Requirement |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | 9.0 – 10.0 | **IMMEDIATE REJECT** | Must be fixed before push. |
| **HIGH** | 7.0 – 8.9 | **REJECT (If fix exists)** | Must be fixed or require SER. |
| **MEDIUM** | 4.0 – 6.9 | **WARN / LOG** | Resolve within 30 days. |
| **LOW** | 0.1 – 3.9 | **LOG ONLY** | Resolve within 90 days. |

---

## 2. Mandatory Image Standards

### 2.1 Base Image Provenance (NIST CM-2)
* All images **must** inherit from the approved "Golden Image" catalog (e.g., Red Hat UBI, Alpine-minimal).
* Use of `latest` tags in `FROM` instructions is forbidden. **SHA256 digests** must be used to ensure immutability.

### 2.2 Layer Security & Secrets (OWASP)
* **Secret Scanning:** Any image layer containing unencrypted credentials, SSH keys, or API tokens will be automatically purged and the developer notified.
* **Minimal Footprint:** Production images must use **Multi-Stage Builds** to ensure compilers, package managers (yum/apt), and shells are removed.

---

## 3. The "Fix Available" Rule (STIG Compliance)
Per **DISA STIG** guidelines:
* If a vulnerability has a **Vendor Fix** available, the image **cannot** be used in production.
* If **No Fix** is available, the image must be moved to a `quarantine` tag and requires a signed **Security Exception Request (SER)** to proceed.

---

## 4. Audit & Alerting Flow
1. **Scan Execution:** Triggered by Registry Webhook (Post-Push).
2. **Analysis:** Result parsed against the thresholds in Section 1.
3. **Notification:** * **Success:** Image is signed via **Cosign** and moved to the `stable` library.
    * **Failure:** Push is blocked. An automated report is sent to the **Security Audit Mailbox** and the image owner.

---

## 5. Security Analysis Mapping
* **V-222645 (STIG):** Automated vulnerability scanning for all hosted images.
* **SI-7 (NIST):** Software integrity checks via SHA256 pinning and Cosign signatures.
* **SC-13 (FIPS):** All scanning operations use FIPS-validated cryptographic modules.

---
**END OF POLICY**