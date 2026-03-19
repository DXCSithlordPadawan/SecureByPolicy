# Pre-Live Deployment Checklist: DevSecOps Gatekeeper

This checklist must be completed and signed off by the **SRE** and **SecOps** leads before the `pre-receive` hooks are enabled on production repositories. It ensures that the infrastructure, permissions, and emergency protocols are verified to prevent accidental developer lockouts.

---

## 1. Infrastructure & Environment
* [ ] **FIPS Mode:** Confirm host-level FIPS is active: `fips-mode-setup --check`.
* [ ] **Podman Storage:** Ensure the `/var/lib/containers` partition has sufficient quota (min 20GB) for the scanner image and temporary scan layers.
* [ ] **Network Routing:** Verify the container can reach the internal SMTP relay:
  `podman run --rm alpine nc -zv [SMTP_SERVER] [PORT]`
* [ ] **Secrets Management:** Confirm `SMTP_PASS` is injected via a secure environment variable or secret mount, **not** hardcoded in the hook script.

---

## 2. Permissions & Hooks
* [ ] **Executable Bit:** `chmod +x /path/to/repo.git/custom_hooks/pre-receive`.
* [ ] **Service Account:** Ensure the Git service user (e.g., `git` or `gitea`) has permission to execute `podman run` without `sudo`.
* [ ] **Read-Only Mounts:** Verify that `local_security.json` is mounted as `:ro` to prevent the container from modifying its own rules.

---

## 3. Policy & Logic Verification (The "Smoke Test")
* [ ] **Positive Test (Clean):** Push a "clean" commit with the `[COMPLIANCE-SCAN-PASSED]` footer to ensure the gate opens for valid work.
* [ ] **Negative Test (Pattern):** Push a commit containing `BEGIN RSA PRIVATE KEY` to verify a **Critical** rejection.
* [ ] **Negative Test (Bypass):** Push with `git push --no-verify` to ensure the server detects the lack of scan evidence.
* [ ] **Mail Delivery:** Confirm the **Security Audit Mailbox** received the alerts from the negative tests above.

---

## 4. Registry Configuration
* [ ] **Trivy Database:** Run `trivy image --download-db-only` on the host to ensure the vulnerability database is primed and ready.
* [ ] **Webhook Latency:** Measure the time from "Push" to "Scan Result." It must be under 60 seconds for a standard 200MB image.
* [ ] **Quarantine Tag:** Verify that rejected images are moved to or remain in a `quarantine` namespace and cannot be pulled by production nodes.

---

## 🚨 Emergency "Break Glass" Protocol
In the event of a system-wide failure of the security gate (e.g., SMTP relay down or Podman engine crash):

1.  **Manual Bypass:** An Administrator can temporarily rename the `pre-receive` hook to `pre-receive.disabled` to allow urgent pushes.
2.  **Audit Requirement:** Any push made during a "Break Glass" event **must** be manually audited within 24 hours.
3.  **Restoration:** Once the issue is resolved, rename the hook back and trigger a manual scan of all commits made during the downtime.

---
**Verified By:** ____________________ (SRE)  
**Approved By:** ____________________ (SecOps)  
**Date:** `YYYY-MM-DD`