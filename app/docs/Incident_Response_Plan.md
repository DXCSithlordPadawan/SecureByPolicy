# Incident Response Plan: Security Gate Events

**Version:** 1.0  
**Compliance Standards:** NIST IR-4, NIST IR-6, NIST AU-12, DISA STIG  
**Maintained By:** SecOps  
**Review Cycle:** Quarterly (align with Break-Glass Drill in Maintenance Schedule)  
**Status:** ACTIVE

---

## Purpose

This plan defines the procedures for detecting, containing, and recovering from security incidents within the **Modular Git Policy Enforcer** system. It covers three primary incident categories:

1. **Security Gate Failure** — the pre-receive hook or Trivy scanner stops functioning
2. **Active Exploit / Policy Bypass** — non-compliant code reaches or attempts to reach production
3. **Break-Glass Window** — authorized temporary bypass of the security gate

All incidents must be documented in the Audit Log and reported to the CISO within the timeframes below.

---

## 1. Severity Classification

| Severity | Description | Example | Max Response Time |
| :--- | :--- | :--- | :--- |
| **P1 — Critical** | Active bypass of security controls; possible data exfiltration | Hardcoded secret reached `main` branch; gate was offline | 1 hour |
| **P2 — High** | Security gate degraded; reduced enforcement | Trivy DB out of date >24 h; notifier not sending alerts | 4 hours |
| **P3 — Medium** | Partial loss of visibility or logging | JSON audit log rotation failed; SIEM feed interrupted | 24 hours |
| **P4 — Low** | Policy violation caught and blocked normally | Developer push rejected; SER filed | Next business day |

---

## 2. Incident Category A: Security Gate Failure

### 2.1 Detection Signals
- The `pre-receive` hook returns exit code `0` for a push that contains known forbidden patterns (false negative).
- The Trivy scan step exits with a non-zero status but the image is promoted anyway.
- No audit log entries written for > 1 hour during active business hours.
- Security Audit Mailbox receives no notifications for > 4 hours during active push activity.

### 2.2 Immediate Containment (≤ 15 minutes)
1. **Identify the failure mode** — check the orchestrator container logs:
   ```bash
   podman logs git-policy-enforcer --tail 100
   ```
2. **Disable the broken hook temporarily** (authorized personnel only):
   ```bash
   mv /path/to/hooks/pre-receive /path/to/hooks/pre-receive.disabled
   ```
3. **Notify the Security Audit Mailbox** manually if automated alerting is also down.
4. **Freeze merge permissions** on the `main` / `release` branches via repository settings until the gate is restored.

### 2.3 Eradication & Recovery (≤ 4 hours)
1. Identify and fix the root cause (container crash, misconfigured rule file, network issue).
2. Validate the fix in a staging environment by pushing a known-bad commit and confirming rejection.
3. Re-enable the hook:
   ```bash
   mv /path/to/hooks/pre-receive.disabled /path/to/hooks/pre-receive
   ```
4. Perform an **emergency audit** of all commits pushed during the failure window (see §5 below).

### 2.4 Post-Incident Actions
- File an incident report within 24 hours (see §6).
- Review root cause to determine whether a rule, configuration, or code change is required.
- Update Maintenance Guide if a new daily/monthly check is warranted.

---

## 3. Incident Category B: Active Exploit / Policy Bypass

### 3.1 Detection Signals
- A commit containing a forbidden pattern (secret, weak crypto, etc.) is found on a protected branch.
- `git log --grep="[COMPLIANCE-SCAN-PASSED]"` reveals commits lacking the evidence stamp on `main`.
- A container image with a CRITICAL CVE is found in the `stable` library.
- An unauthorized `--no-verify` push is confirmed by audit log review.

### 3.2 Immediate Containment (≤ 1 hour — P1)
1. **Revoke the compromised secret immediately** if a credential was exposed. Notify the relevant service owner.
2. **Revert the offending commit**:
   ```bash
   git revert <sha> --no-edit
   git push origin <branch>
   ```
   If the commit is on `main`, coordinate with the SRE team for a force-push under change control.
3. **Quarantine any affected container image**:
   ```bash
   # Move image from stable to quarantine tag in the registry
   podman tag <registry>/<image>@sha256:<digest> <registry>/<image>:quarantine
   podman rmi <registry>/<image>:stable
   ```
4. **Notify CISO within 1 hour** with: affected repository, commit SHA, type of violation, and containment actions taken.

### 3.3 Eradication & Recovery
1. Confirm the offending content is fully removed from all branches (check `git log --all`).
2. Run a full Trivy scan on all images in the `stable` library.
3. Run `orchestrator.py` in audit mode against the full commit history to detect any other missed violations.
4. Restore clean state and verify that the gate correctly blocks a replay of the violation.

### 3.4 Post-Incident Actions
- Conduct a root-cause analysis: was it a gate failure, a rule gap, or a social-engineering bypass?
- Add a new rule to `local_security.json` if a pattern gap is identified.
- Update [Developer Remediation Guide](Developer_Remediation_Guide.md) if the violation type is new.
- File an incident report (§6) within 24 hours.

---

## 4. Incident Category C: Break-Glass Window

A break-glass event is an **authorized, time-limited** bypass of the security gate for emergency production deployments when the gate cannot be fixed in time.

### 4.1 Authorization Requirements
- Requires written approval from **CISO or delegated authority**.
- Duration must be specified (maximum 4 hours without re-authorization).
- All pushes during the window are treated as P1 for post-window audit purposes.

### 4.2 Break-Glass Procedure
1. **Obtain approval** (email or ticket with timestamp) from CISO.
2. **Disable the hook**:
   ```bash
   mv /path/to/hooks/pre-receive /path/to/hooks/pre-receive.disabled
   ```
3. **Start a break-glass log** — record every push SHA manually:
   ```bash
   git log --oneline origin/main..HEAD >> /var/log/break-glass-$(date +%Y%m%d%H%M).log
   ```
4. **Re-enable the hook** immediately after the emergency push completes:
   ```bash
   mv /path/to/hooks/pre-receive.disabled /path/to/hooks/pre-receive
   ```
5. **Manual audit** of every commit pushed during the window must be completed **within 24 hours**.

### 4.3 Post-Break-Glass Audit Checklist
- [ ] All commits pushed during window reviewed for secrets and forbidden patterns
- [ ] All images built during window scanned with Trivy before promotion to `stable`
- [ ] Break-glass log archived to SIEM / Audit Mailbox
- [ ] Incident report filed (§6) within 24 hours

---

## 5. Emergency Audit Procedure

When an audit of commits during a failure window is required:

```bash
# List all commits pushed between two timestamps (adjust as needed)
git log --after="YYYY-MM-DDTHH:MM:SS" --before="YYYY-MM-DDTHH:MM:SS" --oneline

# For each commit SHA, run the orchestrator in audit mode
python3 app/scripts/orchestrator.py --audit-only --sha <commit-sha>

# Or generate a full diff for manual review
git diff <start-sha> <end-sha> > /tmp/audit-diff-$(date +%Y%m%d).patch
```

Results must be stored in the structured audit log and forwarded to the Security Audit Mailbox.

---

## 6. Incident Report Template

File this report within **24 hours** of containment. Submit to `#secops-support` and email to the Security Audit Mailbox.

```
Incident Report
===============
Date/Time Detected  : YYYY-MM-DD HH:MM UTC
Date/Time Contained : YYYY-MM-DD HH:MM UTC
Severity            : P1 / P2 / P3 / P4
Category            : Gate Failure / Active Exploit / Break-Glass
Reporter            : <name, role>

Summary
-------
<One-paragraph description of what occurred>

Affected Resources
------------------
- Repository     : <repo name>
- Branch(es)     : <branch names>
- Commit SHA(s)  : <sha list>
- Image(s)       : <image:digest list, if applicable>

Root Cause
----------
<Technical root-cause analysis>

Containment Actions
-------------------
1. <action taken, timestamp>
2. <action taken, timestamp>

Remediation Actions
-------------------
1. <permanent fix applied>
2. <process/rule change made>

CISO Notified       : Yes / No  (Timestamp: ____)
Audit Log Updated   : Yes / No
SER Filed           : Yes / No  (SER ID: ____)
```

---

## 7. Compliance Mapping

| Control | Standard | Implementation |
| :--- | :--- | :--- |
| Incident Handling | NIST IR-4 | This plan; defined detection, containment, eradication, recovery |
| Incident Reporting | NIST IR-6 | CISO notification within 1 hour for P1; 24-hour report template |
| Audit Record Generation | NIST AU-12 | All containment actions recorded in structured audit log |
| Configuration Management | NIST CM-2 | Hook state changes tracked; reverts documented |
| Non-Repudiation | NIST AU-10 | All break-glass and bypass actions require named authorization |

---

**End of Document**  
*Version 1.0 — Status: ACTIVE — Review Quarterly*
