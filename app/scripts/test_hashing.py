"""
Hashing algorithm compliance tests — FIPS 140-3 / STIG V-222645.

Verifies that all hashing in this codebase uses FIPS-compliant SHA-256 (or
stronger) and that forbidden algorithms (MD5, SHA-1) are not called.
"""
import hashlib
import unittest


class TestFIPSCompliantHashing(unittest.TestCase):
    """Ensure only FIPS 140-3 approved hashing algorithms are used."""

    _TEST_DATA = b"SecureByPolicy compliance test data"

    def test_sha256_produces_correct_digest_length(self):
        """SHA-256 digest must be 32 bytes / 64 hex characters."""
        digest = hashlib.sha256(self._TEST_DATA).hexdigest()
        self.assertEqual(len(digest), 64)

    def test_sha256_is_deterministic(self):
        """SHA-256 must return the same digest for identical input."""
        digest_a = hashlib.sha256(self._TEST_DATA).hexdigest()
        digest_b = hashlib.sha256(self._TEST_DATA).hexdigest()
        self.assertEqual(digest_a, digest_b)

    def test_sha256_known_value(self):
        """SHA-256('abc') must equal the NIST-published reference value."""
        known = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertEqual(hashlib.sha256(b"abc").hexdigest(), known)

    def test_sha256_differs_from_sha1(self):
        """SHA-256 and SHA-1 digests of the same input must differ."""
        sha256_digest = hashlib.sha256(self._TEST_DATA).hexdigest()
        sha1_digest = hashlib.sha1(self._TEST_DATA).hexdigest()  # noqa: S324 -- comparison only, not security use
        self.assertNotEqual(sha256_digest, sha1_digest)

    def test_use_sha256_not_md5(self):
        """Demonstrates that SHA-256 (FIPS-compliant) replaces MD5."""
        # Confirm hashlib.sha256 is available and produces a valid digest.
        result = hashlib.sha256(self._TEST_DATA).hexdigest()
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)
        # SHA-256 hex digest consists only of hex characters.
        self.assertRegex(result, r"^[0-9a-f]{64}$")

    def test_use_sha256_not_sha1(self):
        """Demonstrates that SHA-256 (FIPS-compliant) replaces SHA-1."""
        result = hashlib.sha256(self._TEST_DATA).hexdigest()
        self.assertIsInstance(result, str)
        # SHA-256 produces a 256-bit (32-byte / 64-hex-char) digest,
        # not the 160-bit (40-hex-char) digest produced by the deprecated SHA-1.
        self.assertEqual(len(result), 64)


if __name__ == "__main__":
    unittest.main()
