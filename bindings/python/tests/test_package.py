"""Tests against the installed wheel, with no service or network dependency."""

import unittest
import json
from pathlib import Path

from stogas_verifier import (
    EvidenceSnapshot,
    EvidenceVerifier,
    Transport,
    VerificationError,
    VerifiedBoot,
)

# Local offline trust configuration, never accepted by the managed transport.
_root = json.loads((Path(__file__).resolve().parents[3] / "tests/fixtures/logged-key-manifest.json").read_text())["root"]
ROOT = {"root_key_id": _root["key_id"], "root_public_key": _root["public_key"]}


class PackageTests(unittest.TestCase):
    def test_malformed_evidence_fails_closed(self):
        verifier = EvidenceVerifier(**ROOT)
        for method in (verifier.refresh, verifier.verify_key_manifest, verifier.verify_evidence_archive):
            with self.subTest(method=method.__name__):
                with self.assertRaises(VerificationError) as caught:
                    method(b'{"body":')
                self.assertEqual(caught.exception.code, "invalid_evidence")
        # A rejected candidate cannot leave a forged snapshot behind.
        with self.assertRaises(VerificationError):
            verifier.refresh(b'{}')
        with self.assertRaises(VerificationError):
            verifier.verify_boot_archive(b'{}', b'{}')

    def test_offline_authority_is_explicit(self):
        for options in (
            {"environment": "unknown", **ROOT},
            {"root_key_id": "partial"},
            {"root_public_key": ROOT["root_public_key"]},
            {"root_key_id": "invalid", "root_public_key": "bad-key"},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                EvidenceVerifier(**options)

    def test_verified_values_cannot_be_fabricated(self):
        for value in (EvidenceSnapshot, VerifiedBoot):
            with self.subTest(value=value), self.assertRaises(TypeError):
                value()

    def test_evidence_requires_immutable_bytes(self):
        verifier = EvidenceVerifier(**ROOT)
        for value in (bytearray(b'{}'), memoryview(b'{}'), '{}'):
            with self.subTest(value=type(value)), self.assertRaises(TypeError):
                verifier.refresh(value)

    def test_invalid_transport_options_fail_before_acquisition(self):
        for options in (
            {"environment": "unknown"},
            {"security": "both"},
            {"max_connections": 0},
            {"base_url": "http://api.example"},
            {"base_url": "https://key:secret@api.example"},
            {"base_url": "https://api.example/v1"},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                Transport(**options)

    def test_removed_options_do_not_silently_change_trust(self):
        for options in (
            {"bundle_url": "https://attacker.example"},
            {"hardware_policy": {}},
            {"bundle_refresh_interval_seconds": 300},
        ):
            with self.subTest(options=options), self.assertRaises(TypeError):
                Transport(**options)


if __name__ == "__main__":
    unittest.main()
