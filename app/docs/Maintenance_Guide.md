# SRE Maintenance Schedule: DevSecOps Gates

### Daily (Automated)
* **CVE Sync:** `trivy image --download-db-only`
* **Audit Logs:** Rotate and forward to SIEM/Central Mailbox.

### Monthly (Compliance)
* **Base Image Refresh:** Update `@sha256` digests for UBI images.
* **FIPS Integrity:** Run `fips-mode-setup --check` on host and container.
* **Exception Audit:** Re-validate or revoke any active SERs.

### Quarterly (Drill)
* **Bypass Simulation:** Attempt a "dirty" push to test gate logic.
* **Break-Glass Test:** Practice disabling/enabling the `pre-receive` hook.