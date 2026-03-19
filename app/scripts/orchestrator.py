import sys
import os
import subprocess
import json
import re

class PolicyEnforcer:
    def __init__(self, rules_path="/app/rules/local_security.json"):
        with open(rules_path, 'r') as f:
            self.rules = json.load(f)
        self.evidence_key = "[COMPLIANCE-SCAN-PASSED]"

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

    def run(self):
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
                    sys.exit(1)

                # 2. Pattern Scan
                violations = self.scan_diff(sha)
                if violations:
                    print(f"❌ REJECTED: Security violation in commit {sha[:7]}")
                    for v in violations:
                        print(f" - [{v['severity']}] {v['reason']}")
                        print(f" - Remediation: {v['remediation']}")
                    sys.exit(1)

if __name__ == "__main__":
    enforcer = PolicyEnforcer()
    enforcer.run()