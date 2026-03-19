import sys
import os
import subprocess
import json
import re
import pathlib
from datetime import datetime, timezone
from notifier import NotificationManager

class PolicyEnforcer:
    def __init__(self, rules_path="/app/rules/local_security.json"):
        with open(rules_path, 'r') as f:
            self.rules = json.load(f)
        self.evidence_key = "[COMPLIANCE-SCAN-PASSED]"
        self.notifier = NotificationManager()
        self.audit_log_path = os.getenv("AUDIT_LOG_PATH", "")

    def get_commit_hashes(self, old_rev, new_rev):
        """Returns list of commit hashes between old and new revisions."""
        cmd = ["git", "rev-list", f"{old_rev}..{new_rev}"]
        return subprocess.check_output(cmd).decode().split()

    def check_evidence(self, commit_hash):
        """Ensures the developer didn't bypass local hooks."""
        msg = subprocess.check_output(["git", "log", "-1", "--pretty=%B", commit_hash]).decode()
        return self.evidence_key in msg

    def scan_diff(self, commit_hash):
        """Scans the diff of a commit for forbidden patterns."""
        diff = subprocess.check_output(["git", "show", commit_hash]).decode()
        violations = []
        
        for rule in self.rules.get("forbidden_patterns", []):
            if re.search(rule["pattern"], diff):
                violations.append(rule)
        return violations

    def write_audit_log(self, repo, user, sha, event_type, violation=None, action="rejected"):
        """Writes a structured JSON audit record for NIST AU-12 compliance."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "repo": repo,
            "user": user,
            "sha": sha,
            "event_type": event_type,
            "violation": violation,
            "action": action,
        }
        log_line = json.dumps(record)
        print(f"[AUDIT] {log_line}", file=sys.stderr)
        if self.audit_log_path:
            try:
                pathlib.Path(self.audit_log_path).parent.mkdir(parents=True, exist_ok=True)
                with open(self.audit_log_path, "a") as f:
                    f.write(log_line + "\n")
            except OSError as e:
                print(f"Warning: Could not write audit log to {self.audit_log_path}: {e}", file=sys.stderr)

    def run(self):
        repo = os.getenv("GL_REPOSITORY", os.getenv("REPO_NAME", "unknown"))
        user = os.getenv("GL_USERNAME", os.getenv("GIT_PUSH_USER", "unknown"))

        # Git pre-receive hooks provide (old_rev, new_rev, ref_name) via stdin
        for line in sys.stdin:
            old_rev, new_rev, ref = line.strip().split()
            
            # Handle branch deletions
            if new_rev == "0000000000000000000000000000000000000000":
                continue

            commits = self.get_commit_hashes(old_rev, new_rev)
            for sha in commits:
                # 1. Evidence Check
                if not self.check_evidence(sha):
                    print(f"❌ REJECTED: Commit {sha[:7]} missing compliance evidence.")
                    print("Reason: Local pre-commit hooks were bypassed (--no-verify).")
                    ev = {"reason": "Missing compliance evidence key", "severity": "High"}
                    self.write_audit_log(repo, user, sha, "evidence_missing", violation=ev, action="rejected")
                    self.notifier.send_violation_report(repo, user, ev)
                    sys.exit(1)

                # 2. Pattern Scan
                violations = self.scan_diff(sha)
                if violations:
                    print(f"❌ REJECTED: Security violation in commit {sha[:7]}")
                    for v in violations:
                        print(f" - [{v['severity']}] {v['reason']}")
                        print(f" - Remediation: {v['remediation']}")
                        self.write_audit_log(repo, user, sha, "pattern_violation",
                                             violation={"reason": v["reason"], "severity": v["severity"]},
                                             action="rejected")
                        if v["severity"] in ("High", "Critical"):
                            self.notifier.send_violation_report(repo, user, v)
                    sys.exit(1)

if __name__ == "__main__":
    enforcer = PolicyEnforcer()
    enforcer.run()