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

# Map file extensions to language-specific policy filenames.
# Used by scan_diff_language_specific() to apply targeted rules per file type.
EXTENSION_TO_POLICY = {
    ".py":   "python_policy.json",
    ".js":   "javascript_policy.json",
    ".mjs":  "javascript_policy.json",
    ".cjs":  "javascript_policy.json",
    ".java": "java_policy.json",
    ".cs":   "csharp_policy.json",
    ".ts":   "typescript_policy.json",
    ".tsx":  "react_policy.json",
    ".jsx":  "react_policy.json",
    ".go":   "golang_policy.json",
    ".rs":   "rust_policy.json",
    ".sh":   "bash_policy.json",
    ".bash": "bash_policy.json",
    ".ps1":  "powershell_policy.json",
    ".psm1": "powershell_policy.json",
    ".psd1": "powershell_policy.json",
    ".c":    "c_policy.json",
    ".h":    "c_policy.json",
    ".cpp":  "cpp_policy.json",
    ".cc":   "cpp_policy.json",
    ".cxx":  "cpp_policy.json",
    ".hpp":  "cpp_policy.json",
    ".hh":   "cpp_policy.json",
    # Angular .ts files share the TypeScript mapping; Angular HTML templates use
    # angular_policy.json only when Angular-specific directives are present.
    # To avoid misclassifying plain HTML, .html is not mapped here.
}


# Paths that intentionally reference forbidden algorithm names for educational/
# documentation purposes are excluded from baseline forbidden-pattern scanning.
# Language-specific policy scanning is unaffected and still runs for code files.
# Satisfies: PRD Option A — exclude doc-only paths while keeping code scanning.
BASELINE_SCAN_EXCLUDED_PATHS = (
    "app/docs/",
    "app/standards/",
)


class PolicyEnforcer:
    def __init__(self, rules_path="/app/rules/local_security.json"):
        with open(rules_path, 'r') as f:
            self.rules = json.load(f)
        self.evidence_key = "[COMPLIANCE-SCAN-PASSED]"
        self.notifier = NotificationManager()
        self.audit_log_path = os.getenv("AUDIT_LOG_PATH", "")
        self.rules_dir = pathlib.Path(rules_path).parent
        self._policy_cache: dict = {}

    def get_commit_hashes(self, old_rev, new_rev):
        """Returns list of commit hashes between old and new revisions."""
        cmd = ["git", "rev-list", f"{old_rev}..{new_rev}"]
        return subprocess.check_output(cmd).decode().split()

    def check_evidence(self, commit_hash):
        """Ensures the developer didn't bypass local hooks."""
        msg = subprocess.check_output(["git", "log", "-1", "--pretty=%B", commit_hash]).decode()
        return self.evidence_key in msg

    def _load_language_policy(self, policy_filename: str) -> dict:
        """Loads and caches a language-specific policy JSON file from the rules directory."""
        if policy_filename in self._policy_cache:
            return self._policy_cache[policy_filename]
        policy_path = self.rules_dir / policy_filename
        if policy_path.exists():
            with open(policy_path, 'r') as f:
                policy = json.load(f)
            self._policy_cache[policy_filename] = policy
        else:
            print(f"[WARN] Language policy not found: {policy_path}", file=sys.stderr)
            self._policy_cache[policy_filename] = {}
        return self._policy_cache[policy_filename]

    def scan_diff(self, commit_hash):
        """Scans the diff of a commit against the baseline forbidden patterns.

        Files whose paths start with any entry in BASELINE_SCAN_EXCLUDED_PATHS
        (e.g. app/docs/, app/standards/) are excluded so that documentation and
        standards guides that intentionally mention forbidden algorithm names do
        not trigger false-positive violations.  Language-specific policy scanning
        via scan_diff_language_specific() is unaffected.
        """
        diff = subprocess.check_output(["git", "show", commit_hash]).decode()

        # Split the diff into per-file sections and drop excluded paths.
        # Each file section starts with a "diff --git a/<path> b/<path>" header.
        file_sections = re.split(r'(?=^diff --git )', diff, flags=re.MULTILINE)
        filtered_sections = []
        for section in file_sections:
            header_match = re.match(r'^diff --git a/(\S+)', section)
            if header_match:
                file_path = header_match.group(1)
                if any(file_path.startswith(excl) for excl in BASELINE_SCAN_EXCLUDED_PATHS):
                    continue
            filtered_sections.append(section)
        filtered_diff = "".join(filtered_sections)

        violations = []
        for rule in self.rules.get("forbidden_patterns", []):
            if re.search(rule["pattern"], filtered_diff):
                violations.append(rule)
        return violations

    def scan_diff_language_specific(self, commit_hash):
        """Scans changed files in a commit against language-specific security policies.

        Extracts the content of each modified file at the given commit and applies
        the corresponding language policy based on the file's extension.
        Satisfies: NIST SA-11, OWASP Top 10 language-specific controls.
        """
        changed_files_output = subprocess.check_output(
            ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", "--diff-filter=ACM",
             commit_hash]
        ).decode()
        changed_files = changed_files_output.splitlines()

        violations = []
        seen_policies: set = set()

        for rel_path in changed_files:
            ext = pathlib.Path(rel_path).suffix.lower()
            policy_filename = EXTENSION_TO_POLICY.get(ext)
            if not policy_filename:
                continue

            policy = self._load_language_policy(policy_filename)
            patterns = policy.get("forbidden_patterns", [])
            if not patterns:
                continue

            # Retrieve the file content at this specific commit for targeted scanning
            try:
                content = subprocess.check_output(
                    ["git", "show", f"{commit_hash}:{rel_path}"],
                    stderr=subprocess.DEVNULL
                ).decode(errors="replace")
            except subprocess.CalledProcessError:
                continue

            standard = policy.get("standard") or "Language-Specific Policy"
            for rule in patterns:
                # Deduplicate: report each (pattern, file) violation once
                violation_key = (rule["pattern"], rel_path)
                if violation_key in seen_policies:
                    continue
                if re.search(rule["pattern"], content):
                    seen_policies.add(violation_key)
                    enriched = dict(rule)
                    enriched["file"] = rel_path
                    enriched["standard"] = standard
                    violations.append(enriched)

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
        skip_evidence = os.getenv("SKIP_EVIDENCE_CHECK", "false").lower() == "true"

        # Git pre-receive hooks provide (old_rev, new_rev, ref_name) via stdin
        for line in sys.stdin:
            old_rev, new_rev, ref = line.strip().split()
            
            # Handle branch deletions
            if new_rev == "0000000000000000000000000000000000000000":
                continue

            commits = self.get_commit_hashes(old_rev, new_rev)
            for sha in commits:
                # 1. Evidence Check (skipped in CI via SKIP_EVIDENCE_CHECK=true)
                if not skip_evidence and not self.check_evidence(sha):
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

                # 3. Language-Specific Policy Scan (NIST SA-11, OWASP Top 10)
                lang_violations = self.scan_diff_language_specific(sha)
                if lang_violations:
                    print(f"❌ REJECTED: Language-policy violation in commit {sha[:7]}")
                    for v in lang_violations:
                        file_info = f" (file: {v['file']})" if v.get("file") else ""
                        std_info = f" [{v['standard']}]" if v.get("standard") else ""
                        print(f" - [{v['severity']}]{std_info} {v['reason']}{file_info}")
                        print(f" - Remediation: {v['remediation']}")
                        self.write_audit_log(repo, user, sha, "language_policy_violation",
                                             violation={"reason": v["reason"], "severity": v["severity"],
                                                        "file": v.get("file"), "standard": v.get("standard")},
                                             action="rejected")
                        if v["severity"] in ("High", "Critical"):
                            self.notifier.send_violation_report(repo, user, v)
                    sys.exit(1)

                # 4. Bandit Static Analysis (DISA STIG V-222637)
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
    rules_path = os.getenv("RULES_PATH", "/app/rules/local_security.json")
    enforcer = PolicyEnforcer(rules_path=rules_path)
    enforcer.run()