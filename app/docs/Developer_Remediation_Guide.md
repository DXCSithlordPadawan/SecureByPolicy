# Developer Remediation Guide: Security Push-Gates

This guide provides instructions on how to resolve a **Push Rejection** from the Modular Git Policy Enforcer. Our security gates are "Manual Remediation Only"—this ensures you understand the vulnerability and maintains an audit trail of your fix.

---

## 1. How to Read a Rejection Message
When a `git push` is blocked, your terminal will display a structured error message:

> **❌ PUSH REJECTED by Security Policy Enforcer**
> **File:** `src/auth/service.py`
> **Line:** 42
> **Violation:** `MD5` detected (STIG V-222645)
> **Severity:** High
> **Remediation:** Use a FIPS-compliant hashing algorithm (SHA256 or higher).

---

## 2. Common Violations & Fixes

### 2.1 Hardcoded Secrets (OWASP A07)
* **Error:** `BEGIN RSA PRIVATE KEY` or `AWS_SECRET_KEY` detected.
* **The Fix:** 1. Remove the secret from the file.
    2. Move the secret to the **Vault** or use **Environment Variables**.
    3. **Crucial:** If the secret was committed, it is now compromised. Rotate the credential immediately.

### 2.2 Weak Cryptography (NIST/STIG)
* **Error:** `MD5` or `SHA1` detected.
* **The Fix:** 1. Replace the library call with a secure alternative (e.g., `hashlib.sha256()`).
    2. If the weak hash is required for legacy checksums (non-security), you must file a **Security Exception Request (SER)**.

### 2.3 Missing Scan Evidence (NIST SI-7)
* **Error:** `Missing local scan signature in commit message.`
* **The Fix:** 1. You likely bypassed your local hooks with `--no-verify`.
    2. Run your local hooks manually: `pre-commit run --all-files`.
    3. Re-commit your changes to ensure the `[COMPLIANCE-SCAN-PASSED]` footer is generated.

---

## 3. Resolving the Block

Follow these steps to clear a rejection and successfully push your code:

1.  **Apply the Fix:** Modify the code locally based on the terminal feedback.
2.  **Stage Changes:** `git add <filename>`
3.  **Amend the Commit:** Do not create a new "fix" commit. Amend the rejected one:
    ```bash
    git commit --amend --no-edit
    ```
    *Note: If your local hooks are configured correctly, this will re-generate the scan evidence footer.*
4.  **Re-Push:** ```bash
    git push origin <branch-name>
    ```

---

## 4. Requesting an Exception
If you believe a flag is a **False Positive** or there is **No Available Patch** for a container vulnerability:
1.  Open the **Security Exception Request (SER)** template.
2.  Fill in the CVE/Violation details and your technical justification.
3.  Submit to the `#secops-support` channel.
4.  Once approved, SecOps will whitelist your specific commit SHA or image digest.

---

## 🆘 Need Help?
* **Documentation:** [Link to Master Security Handbook]
* **Slack/Teams:** `#secops-support`
* **Policy Rules:** View `local_security.json` in the root of the repo for a full list of forbidden patterns.