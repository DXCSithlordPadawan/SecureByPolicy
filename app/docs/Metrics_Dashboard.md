# Metrics Dashboard: SecureByPolicy — Security KPIs

**Version:** 1.0  
**Compliance Standards:** NIST AU-12, NIST CA-7, PRD §5 Success Metrics  
**Maintained By:** SecOps / SRE  
**Reporting Cadence:** Weekly snapshot; Monthly trend review  
**Status:** ACTIVE

---

## Purpose

This document defines the **Key Performance Indicators (KPIs)** and measurement methodology for the Modular Git Policy Enforcer, as required by PRD §5. It provides the framework for tracking security gate effectiveness, developer remediation speed, and audit readiness.

The three headline metrics from PRD §5 are:

| Metric | PRD Target | Owner |
| :--- | :--- | :--- |
| **Zero Bypass Rate** | 100 % of production-bound code passes the server-side gate | SecOps |
| **Remediation Speed** | Reduction in time-to-fix measured via CVSS/STIG terminal feedback | SecOps / Dev Leads |
| **Audit Readiness** | Complete violation + exception history retrievable within 10 minutes | SecOps / SRE |

---

## 1. Zero Bypass Rate

### 1.1 Definition
The percentage of commits merged to protected branches (`main`, `release/*`) that passed through the server-side pre-receive gate **without a `--no-verify` bypass or break-glass window**.

> **Target: 100 %**  
> Any value below 100 % is a P1 security incident.

### 1.2 Measurement Method

```bash
# Count total commits to main in the period
TOTAL=$(git log origin/main --after="YYYY-MM-DD" --before="YYYY-MM-DD" --oneline | wc -l)

# Count commits WITH the compliance evidence stamp
PASSED=$(git log origin/main --after="YYYY-MM-DD" --before="YYYY-MM-DD" \
         --grep="\[COMPLIANCE-SCAN-PASSED\]" --oneline | wc -l)

# Zero Bypass Rate = PASSED / TOTAL * 100
echo "Zero Bypass Rate: $(echo "scale=2; $PASSED / $TOTAL * 100" | bc)%"
```

Additionally, query the JSON audit log for events with `"action": "REJECTED"` to count blocked pushes and compare to total push events.

### 1.3 Tracking Table (Weekly)

| Week | Total Commits | Gate-Passed | Bypassed | Bypass Rate | Break-Glass Events | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| Template | 0 | 0 | 0 | — | 0 | Update weekly from audit log |

### 1.4 Alert Threshold
- Any bypass event automatically triggers a P1 notification to the Security Audit Mailbox (via `notifier.py`).
- Weekly bypass rate > 0 % triggers a mandatory review with CISO within 5 business days.

---

## 2. Remediation Speed

### 2.1 Definition
The average elapsed time between a push rejection and a successful re-push of the same commit (after the developer applies the fix). Measured per violation severity.

> **Targets:**  
> - Critical: ≤ 4 hours  
> - High: ≤ 8 hours  
> - Medium: ≤ 30 days  
> - Low: ≤ 90 days

### 2.2 Measurement Method
Each rejection event in the JSON audit log records `{timestamp, sha, user, severity, violation}`.  
The corresponding re-push (successful) event records `{timestamp, sha}`.  
Remediation time = `success_timestamp − rejection_timestamp`.

```python
# Pseudocode for log-based calculation
import json
from datetime import datetime

rejections = {}
remediation_times = []

with open("/var/log/secbypolicy-audit.jsonl") as f:
    for line in f:
        event = json.loads(line)
        if event["action"] == "REJECTED":
            rejections[event["user"]] = event
        elif event["action"] == "ALLOWED" and event["user"] in rejections:
            delta = datetime.fromisoformat(event["timestamp"]) - \
                    datetime.fromisoformat(rejections[event["user"]]["timestamp"])
            remediation_times.append((event["user"], delta, rejections.pop(event["user"])["severity"]))
```

### 2.3 Tracking Table (Monthly)

| Month | Violations (Critical) | Avg Fix Time (C) | Violations (High) | Avg Fix Time (H) | SERs Filed | SERs Approved |
| :--- | :---: | :--- | :---: | :--- | :---: | :---: |
| Template | 0 | — | 0 | — | 0 | 0 |

### 2.4 Improvement Levers
- Increase specificity of remediation messages in `local_security.json` (`"remediation"` field).
- Update [Developer Remediation Guide](Developer_Remediation_Guide.md) with new violation types.
- Run quarterly developer security training when monthly average fix time for Critical violations exceeds 4 hours.

---

## 3. Audit Readiness

### 3.1 Definition
The ability to produce a **complete, accurate history** of all security violations, gate decisions, and signed exceptions within **10 minutes** of an auditor request (PRD §5).

### 3.2 Readiness Checklist (Run Before Each Audit)

- [ ] JSON audit log is available and covers the requested date range without gaps
- [ ] Audit log is stored in SIEM / append-only storage (not only on the Git server)
- [ ] All Security Exception Requests (SERs) are filed and linked to specific commit SHAs or image digests
- [ ] Break-glass event logs are archived and time-stamped
- [ ] Trivy scan reports for all images currently in the `stable` library are available
- [ ] Cosign signatures for all `stable` images are verifiable
- [ ] SMTP notification logs confirm Security Audit Mailbox was alerted for all High/Critical violations

### 3.3 10-Minute Audit Response Procedure

| Step | Action | Expected Time |
| :--- | :--- | :---: |
| 1 | Pull JSON audit log for the requested period from SIEM | ≤ 2 min |
| 2 | Filter to `"action": "REJECTED"` events; export to CSV | ≤ 1 min |
| 3 | Join with SER records to show approved exceptions | ≤ 2 min |
| 4 | Pull Trivy scan reports for the requested images | ≤ 2 min |
| 5 | Confirm Cosign signatures on all `stable` images | ≤ 2 min |
| 6 | Deliver package to auditor | ≤ 1 min |
| **Total** | | **≤ 10 min** |

### 3.4 Tracking Table (Monthly)

| Month | Audit Exercises | Avg Retrieval Time | Gaps Found | Remediation |
| :--- | :---: | :--- | :---: | :--- |
| Template | 0 | — | 0 | — |

### 3.5 Gap Indicators
The following conditions indicate that audit readiness has degraded and must be remediated before the next external audit:

| Indicator | Threshold | Action |
| :--- | :--- | :--- |
| JSON audit log gap (missing hours) | > 0 gaps | Investigate log pipeline; restore from backup |
| Retrieval time exceeds target | > 10 minutes | Improve SIEM indexing; rehearse procedure |
| SER without linked commit SHA | Any | SecOps to back-fill missing SER metadata |
| Trivy report older than 24 hours | Any `stable` image | Re-scan immediately |

---

## 4. Continuous Monitoring Integration

| Source | Data Feed | Frequency |
| :--- | :--- | :--- |
| `orchestrator.py` JSON audit log | Violations, allowed pushes, user, SHA, severity | Per-push event |
| Trivy scan results | CVE count by severity per image | Per-image push |
| SMTP notification log | Alert delivery confirmation | Per-alert event |
| SER tracking (Jira / ticket system) | Open/closed exception count | Daily sync |
| Break-glass log | Bypass windows, authorizing officer, commits | Per-event |

---

## 5. Compliance Mapping

| Control | Standard | Metric |
| :--- | :--- | :--- |
| Continuous Monitoring | NIST CA-7 | All three KPIs reviewed weekly/monthly |
| Audit Record Generation | NIST AU-12 | Audit Readiness (§3) |
| Accountability / Non-Repudiation | NIST AU-10 | Zero Bypass Rate (§1) |
| Vulnerability Response | DISA STIG / NIST SI-2 | Remediation Speed (§2) |
| Configuration Management | NIST CM-2 | Image digest tracking in Audit Readiness |

---

## 6. Dashboard Snapshot Template

Copy and fill in after each weekly review:

```
=== SecureByPolicy Weekly Security KPI Snapshot ===
Period        : YYYY-MM-DD to YYYY-MM-DD
Prepared By   : <name, role>
Reviewed By   : <SecOps lead>

ZERO BYPASS RATE
  Total Commits to main       : ___
  Gate-Passed                 : ___
  Bypassed (--no-verify)      : ___
  Break-Glass Events          : ___
  Zero Bypass Rate            : ___%  [Target: 100%]

REMEDIATION SPEED
  Critical Violations         : ___   Avg Fix Time: ___h  [Target: ≤ 4h]
  High Violations             : ___   Avg Fix Time: ___h  [Target: ≤ 8h]
  SERs Filed / Approved       : ___ / ___

AUDIT READINESS
  Log Coverage                : ✅ / ❌
  Last Retrieval Drill        : ____  Duration: ___min  [Target: ≤ 10min]
  Open SERs Without SHA       : ___
  Stale Trivy Reports         : ___

ACTION ITEMS
  1.
  2.
```

---

**End of Document**  
*Version 1.0 — Status: ACTIVE — Review Monthly*
