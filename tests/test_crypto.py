import unittest
import json
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.crypto import (
    canonical_json_bytes,
    sha256_hex,
    compute_input_digest,
    compute_proposal_digest,
    jwk_to_ed25519_public_key,
    verify_receipt_signature
)


class TestCryptoUtils(unittest.TestCase):

    def test_canonical_json_bytes(self):
        # Nested keys must be sorted alphabetically
        data1 = {"z": 1, "a": {"d": 4, "b": 2}}
        data2 = {"a": {"b": 2, "d": 4}, "z": 1}
        self.assertEqual(canonical_json_bytes(data1), canonical_json_bytes(data2))
        self.assertEqual(canonical_json_bytes(data1), b'{"a":{"b":2,"d":4},"z":1}')

    def test_proposal_digest_sorting(self):
        prop1 = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": "INFORMATIONAL", "referenceId": "ref-1"},
            "evidence": ["line_b", "line_a"]
        }
        prop2 = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": "INFORMATIONAL", "referenceId": "ref-1"},
            "evidence": ["line_a", "line_b"]
        }
        # Evidence ordering should produce the exact same digest
        self.assertEqual(compute_proposal_digest(prop1), compute_proposal_digest(prop2))

    def test_ed25519_jwk_and_verification(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        raw_pub = pub.public_bytes_raw()
        x_b64 = base64.urlsafe_b64encode(raw_pub).decode('utf-8').rstrip('=')

        jwk = {"kty": "OKP", "crv": "Ed25519", "x": x_b64}
        imported_pub = jwk_to_ed25519_public_key(jwk)

        eval_id = "eval-test-123"
        input_digest = "abc1234567890"

        receipt = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "no_action",
            "accepted": True,
            "proposalDigest": "digest-123",
            "receiptId": "nonce-999"
        }

        envelope = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "inputDigest": input_digest,
            "receipt": receipt
        }
        sig = priv.sign(canonical_json_bytes(envelope))
        sig_b64 = base64.b64encode(sig).decode('utf-8')

        receipt_with_sig = dict(receipt)
        receipt_with_sig["receiptSignature"] = sig_b64

        # Verify valid signature
        is_valid = verify_receipt_signature(imported_pub, eval_id, input_digest, receipt_with_sig)
        self.assertTrue(is_valid)

        # Verify tampered receipt fails
        tampered_receipt = dict(receipt_with_sig)
        tampered_receipt["accepted"] = False
        self.assertFalse(verify_receipt_signature(imported_pub, eval_id, input_digest, tampered_receipt))

        # Verify tampered input_digest fails
        self.assertFalse(verify_receipt_signature(imported_pub, eval_id, "wrong_digest", receipt_with_sig))


if __name__ == '__main__':
    unittest.main()
