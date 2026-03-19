"""
Unit tests for the baseline forbidden-pattern scan path-exclusion logic.

Validates that files under app/docs/ and app/standards/ are skipped during
baseline scanning while code files are still checked.
Satisfies requirement: Option A — exclude documentation paths from baseline scan.
"""
import re
import sys
import os
import unittest

# Allow importing orchestrator without its optional runtime dependencies.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from orchestrator import BASELINE_SCAN_EXCLUDED_PATHS  # noqa: E402


def _filter_diff(diff: str) -> str:
    """Mirror the filtering logic in PolicyEnforcer.scan_diff()."""
    file_sections = re.split(r'(?=^diff --git )', diff, flags=re.MULTILINE)
    filtered_sections = []
    for section in file_sections:
        header_match = re.match(r'^diff --git a/(\S+)', section)
        if header_match:
            file_path = header_match.group(1)
            if any(file_path.startswith(excl) for excl in BASELINE_SCAN_EXCLUDED_PATHS):
                continue
        filtered_sections.append(section)
    return "".join(filtered_sections)


def _make_diff_section(file_path: str, added_content: str) -> str:
    """Build a minimal git-diff section for a single file."""
    return (
        f"diff --git a/{file_path} b/{file_path}\n"
        f"index 0000000..1111111 100644\n"
        f"--- a/{file_path}\n"
        f"+++ b/{file_path}\n"
        f"@@ -0,0 +1,1 @@\n"
        f"+{added_content}\n"
    )


class TestBaselineScanExclusions(unittest.TestCase):

    # ------------------------------------------------------------------ #
    # Paths that should be excluded                                        #
    # ------------------------------------------------------------------ #

    def test_docs_file_with_md5_not_flagged(self):
        """MD5 in app/docs/ must not trigger a baseline violation."""
        diff = _make_diff_section("app/docs/Developer_Remediation_Guide.md",
                                  "Do not use MD5 or SHA1 for security-sensitive hashing.")
        filtered = _filter_diff(diff)
        self.assertNotIn("MD5", filtered)
        self.assertNotIn("SHA1", filtered)

    def test_standards_file_with_sha1_not_flagged(self):
        """SHA-1 in app/standards/ must not trigger a baseline violation."""
        diff = _make_diff_section("app/standards/Python_Security_Best_Practices_Guide.md",
                                  "Avoid SHA-1 and MD5; prefer SHA-256 or stronger.")
        filtered = _filter_diff(diff)
        self.assertNotIn("SHA-1", filtered)
        self.assertNotIn("MD5", filtered)

    def test_docs_subdirectory_excluded(self):
        """Files in nested subdirectories of app/docs/ are also excluded."""
        diff = _make_diff_section("app/docs/subdir/example.md",
                                  "hashlib.md5() is forbidden.")
        filtered = _filter_diff(diff)
        self.assertNotIn("md5", filtered)

    # ------------------------------------------------------------------ #
    # Paths that should still be scanned                                   #
    # ------------------------------------------------------------------ #

    def test_source_file_with_md5_is_flagged(self):
        """MD5 in app/scripts/ must still appear in the filtered diff."""
        diff = _make_diff_section("app/scripts/utils.py",
                                  "digest = hashlib.md5(data).hexdigest()")
        filtered = _filter_diff(diff)
        self.assertIn("md5", filtered)

    def test_rules_file_preserved(self):
        """Files in app/rules/ must still appear in the filtered diff."""
        diff = _make_diff_section("app/rules/local_security.json",
                                  '{"pattern": "\\\\bMD5\\\\b"}')
        filtered = _filter_diff(diff)
        self.assertIn("MD5", filtered)

    def test_root_file_preserved(self):
        """Files at the repo root are not excluded."""
        diff = _make_diff_section("README.md",
                                  "Some mention of MD5 in README.")
        filtered = _filter_diff(diff)
        self.assertIn("MD5", filtered)

    # ------------------------------------------------------------------ #
    # Mixed diff: doc + code in the same commit                           #
    # ------------------------------------------------------------------ #

    def test_mixed_diff_only_code_portion_remains(self):
        """When a commit touches both a doc and a code file, only the code
        file section survives in the filtered diff."""
        doc_section = _make_diff_section(
            "app/docs/Master_Security_Handbook.md",
            "Do not use MD5 (hashlib.md5()) for any security-critical purpose."
        )
        code_section = _make_diff_section(
            "app/scripts/crypto.py",
            "# Uses SHA-256 — compliant"
        )
        diff = doc_section + code_section
        filtered = _filter_diff(diff)

        # Doc content must be gone
        self.assertNotIn("Master_Security_Handbook.md", filtered)
        # Code content must remain
        self.assertIn("crypto.py", filtered)

    # ------------------------------------------------------------------ #
    # Constant integrity checks                                            #
    # ------------------------------------------------------------------ #

    def test_excluded_paths_constant_contains_docs(self):
        """BASELINE_SCAN_EXCLUDED_PATHS must include app/docs/."""
        self.assertIn("app/docs/", BASELINE_SCAN_EXCLUDED_PATHS)

    def test_excluded_paths_constant_contains_standards(self):
        """BASELINE_SCAN_EXCLUDED_PATHS must include app/standards/."""
        self.assertIn("app/standards/", BASELINE_SCAN_EXCLUDED_PATHS)


if __name__ == "__main__":
    unittest.main()
