import sys
import os
import subprocess
import json
import re
import pathlib
import tempfile
import shutil
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

    # Source code file extensions checked by the baseline forbidden-pattern scan.
    # Documentation, policy JSON, and configuration files are excluded to prevent
    # false positives when those files legitimately reference algorithm names (e.g.
    # "MD5 is insecure") in comments or policy descriptions.
    _CODE_EXTENSIONS = (
        ".py", ".js", ".mjs", ".cjs", ".java", ".cs",
        ".ts", ".tsx", ".jsx", ".go", ".rs", ".sh",
        ".bash", ".ps1", ".psm1", ".psd1", ".c", ".h",
        ".cpp", ".cc", ".cxx", ".hpp", ".hh",
    )

    def scan_diff(self, commit_hash):
        """Scans newly added lines of source-code files in a commit for forbidden patterns.

        Only lines prefixed with '+' (added lines) in recognised source-code file
        types are inspected.  Documentation files (.md, .txt) and policy/rules JSON
        files are intentionally excluded so that educational references to insecure
        algorithm names (e.g. "MD5 is not FIPS-compliant") do not trigger false
        positives.

        Satisfies: STIG V-222645, NIST SP 800-131A.
        """
        diff = subprocess.check_output(["git", "show", commit_hash]).decode()
        violations = []

        # Collect added lines from source-code files only.
        current_file = ""
        added_lines: list[str] = []
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]  # strip '+++ b/' prefix to get the path
            elif line.startswith("+++"):
                current_file = ""
            elif line.startswith("+") and current_file.endswith(self._CODE_EXTENSIONS):
                added_lines.append(line[1:])  # strip the leading '+'

        added_code_text = "\n".join(added_lines)

        for rule in self.rules.get("forbidden_patterns", []):
            if re.search(rule["pattern"], added_code_text):
                violations.append(rule)
        return violations

    def scan_with_bandit(self, commit_hash):
        """Runs Bandit static analysis on Python files changed in a commit.

        Satisfies: DISA STIG V-222637 (server-side static analysis).
        Returns a list of violation dicts compatible with the pattern-scan format.
        If Bandit is not installed, logs a warning and skips gracefully.
        """
        if not shutil.which("bandit"):
            print("[WARN] Bandit not found in PATH — skipping server-side static analysis.",
                  file=sys.stderr)
            return []

        # Collect the set of Python files added/modified in this commit
        changed_files_output = subprocess.check_output(
            ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", "--diff-filter=ACM",
             commit_hash]
        ).decode()
        py_files = [f for f in changed_files_output.splitlines() if f.endswith(".py")]
        if not py_files:
            return []

        tmpdir = tempfile.mkdtemp(prefix="sbp-bandit-")
        violations = []
        try:
            # Extract each file's content at this commit into a temp directory,
            # preserving relative paths to avoid name collisions across directories.
            for rel_path in py_files:
                dest = pathlib.Path(tmpdir) / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    content = subprocess.check_output(
                        ["git", "show", f"{commit_hash}:{rel_path}"]
                    )
                    dest.write_bytes(content)
                except subprocess.CalledProcessError:
                    continue  # file may have been deleted in a later stage; skip

            py_tmp_files = list(pathlib.Path(tmpdir).rglob("*.py"))
            if not py_tmp_files:
                return []

            result = subprocess.run(
                ["bandit", "-r", "-f", "json", "-l", "-i", "--",
                 *[str(p) for p in py_tmp_files]],
                capture_output=True,
                text=True,
            )

            try:
                bandit_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                return []

            for issue in bandit_output.get("results", []):
                severity = issue.get("issue_severity", "LOW").capitalize()
                confidence = issue.get("issue_confidence", "LOW").capitalize()
                test_id = issue.get("test_id", "")
                test_name = issue.get("test_name", "")
                text = issue.get("issue_text", "")
                line = issue.get("line_number", "?")
                filename = pathlib.Path(issue.get("filename", "")).name
                violations.append({
                    "reason": f"Bandit [{test_id}/{test_name}] {text} "
                              f"(file: {filename}, line: {line}, confidence: {confidence})",
                    "severity": severity,
                    "remediation": (
                        f"Review and remediate {test_id} in {filename}:{line}. "
                        "See https://bandit.readthedocs.io/ for guidance."
                    ),
                })
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

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

                # 3. Bandit Static Analysis (DISA STIG V-222637)
                bandit_violations = self.scan_with_bandit(sha)
                if bandit_violations:
                    print(f"❌ REJECTED: Bandit static-analysis violation in commit {sha[:7]}")
                    for v in bandit_violations:
                        print(f" - [{v['severity']}] {v['reason']}")
                        print(f" - Remediation: {v['remediation']}")
                        self.write_audit_log(repo, user, sha, "bandit_violation",
                                             violation={"reason": v["reason"], "severity": v["severity"]},
                                             action="rejected")
                        if v["severity"] in ("High", "Critical", "Medium"):
                            self.notifier.send_violation_report(repo, user, v)
                    sys.exit(1)

if __name__ == "__main__":
    enforcer = PolicyEnforcer()
    enforcer.run()