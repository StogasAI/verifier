"""Positive snapshot ownership through an explicitly staging-enabled wheel."""

import gc
import base64
import hashlib
import json
import os
from pathlib import Path
import unittest

from stogas_verifier import EvidenceVerifier, VerificationError


@unittest.skipUnless(os.environ.get("STOGAS_TEST_STAGING") == "1", "requires staging wheel")
class StagingEvidenceTests(unittest.TestCase):
    def test_boot_archive_keeps_receipt_owner_without_restoring_live_permission(self):
        fixture = json.loads(
            (Path(__file__).resolve().parents[3] / "tests/fixtures/hardware-session-v1.json").read_bytes()
        )
        verifier = EvidenceVerifier(
            environment="staging",
            root_key_id=fixture["root"]["key_id"],
            root_public_key=fixture["root"]["public_key"],
        )
        # Extract fixed fixture fields; the packaged Rust core authenticates them below.
        encoded = fixture["e2ee"]["response"]
        evidence = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))[1198:]
        start = 1186 + int.from_bytes(evidence[1184:1186], "big")
        size = int.from_bytes(evidence[start:start + 4], "big")
        boot_bytes = evidence[start + 4:start + 4 + size]
        proof_start = start + 4 + size
        archive = {
            "boot": json.loads(boot_bytes),
            "inclusion": json.loads(evidence[proof_start + 4:]),
            "evidence_sha256": fixture["bundle"]["body_sha256"],
        }
        bundle = json.dumps(fixture["bundle"]).encode()
        summary = json.loads(verifier.verify_evidence_archive(bundle))
        self.assertEqual(summary["body_sha256"], archive["evidence_sha256"])
        verified = verifier.verify_boot_archive(json.dumps(archive).encode(), bundle)
        archive["evidence_sha256"] = "0" * 64
        with self.assertRaises(VerificationError):
            verifier.verify_boot_archive(json.dumps(archive).encode(), bundle)
        del verifier
        gc.collect()
        self.assertEqual(json.loads(verified.summary())["boot_sha256"], hashlib.sha256(boot_bytes).hexdigest())
        # Historical handles retain the same receipt verification boundary.
        with self.assertRaises(VerificationError):
            verified.verify_receipt(b'{}', bytes(32), bytes(32))
        vector = json.loads(
            (Path(__file__).resolve().parents[3] / "tests/fixtures/content-receipt-v1.json").read_bytes()
        )
        metadata = {**vector["metadata"], "receipt": vector["hardware_receipt"]}
        request = hashlib.sha256(vector["request"].encode()).digest()
        response = hashlib.sha256(vector["response"].encode()).digest()
        receipt = json.loads(verified.verify_receipt(json.dumps(metadata).encode(), request, response))
        self.assertEqual(receipt["boot_sha256"], hashlib.sha256(boot_bytes).hexdigest())
        metadata["provider"]["instance"] = "substituted"
        with self.assertRaises(VerificationError):
            verified.verify_receipt(json.dumps(metadata).encode(), request, response)

    def test_snapshot_survives_rejected_refresh_and_verifier_destruction(self):
        fixture = json.loads(
            (Path(__file__).resolve().parents[3] / "tests/fixtures/current-evidence-v1.json").read_bytes()
        )
        verifier = EvidenceVerifier(
            environment="staging",
            root_key_id=fixture["root"]["key_id"],
            root_public_key=fixture["root"]["public_key"],
        )
        snapshot = verifier.refresh(json.dumps(fixture["bundle"]).encode())
        expected = json.loads(snapshot.summary())
        self.assertEqual(len(expected["gateways"]), 1)
        self.assertEqual(len(expected["catalogs"]), 2)
        snapshot.require_current_keys()

        with self.assertRaises(VerificationError) as caught:
            verifier.refresh(b'{}')
        self.assertEqual(caught.exception.code, "invalid_evidence")
        del verifier
        gc.collect()
        self.assertEqual(json.loads(snapshot.summary()), expected)
        snapshot.require_current_keys()

        with self.assertRaises(ValueError):
            snapshot.verify_registration(b'{}', b"too-short")
        with self.assertRaises(VerificationError):
            snapshot.verify_logged_boot(b'{}', b'{}')
        with self.assertRaises(VerificationError) as caught:
            snapshot.collateral_validity("00" * 64, "00" * 8)
        self.assertEqual(caught.exception.code, "missing_collateral")


if __name__ == "__main__":
    unittest.main()
