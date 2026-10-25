import json
import hashlib
import base64
from typing import Any, Dict, List, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = "ga5-mailroom-action-gate/v2"


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Encodes an object to UTF-8 bytes of recursively key-sorted, compact JSON.
    Arrays preserve their order, and JSON primitives use normal spelling.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    ).encode('utf-8')


def sha256_hex(data: bytes) -> str:
    """Computes lowercase SHA-256 hex string."""
    return hashlib.sha256(data).hexdigest().lower()


def compute_input_digest(dossiers: List[Dict[str, Any]]) -> str:
    """
    Computes inputDigest over UTF-8 bytes of dossiers encoded as
    recursively key-sorted, compact JSON.
    """
    return sha256_hex(canonical_json_bytes(dossiers))


def compute_proposal_digest(proposal: Dict[str, Any]) -> str:
    """
    Computes proposalDigest:
    Keep exactly dossierId, callId, action, target (null when absent),
    payload, and evidence; sort the evidence strings; then hash the
    recursively key-sorted compact JSON view.
    """
    evidence = proposal.get("evidence", [])
    if isinstance(evidence, list):
        sorted_evidence = sorted(list(set(evidence)))
    else:
        sorted_evidence = []

    normalized = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target") if proposal.get("target") is not None else None,
        "payload": proposal.get("payload", {}),
        "evidence": sorted_evidence
    }
    return sha256_hex(canonical_json_bytes(normalized))


def jwk_to_ed25519_public_key(jwk: Dict[str, Any]) -> Ed25519PublicKey:
    """
    Imports an Ed25519 public key from a JWK (JSON Web Key).
    Format: {"kty":"OKP", "crv":"Ed25519", "x":"<base64url public key>"}
    """
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("Unsupported or invalid Ed25519 JWK key type/curve")
    
    x_b64url = jwk.get("x", "")
    if not x_b64url:
        raise ValueError("Missing 'x' in JWK")

    # Add required base64url padding
    padding = '=' * ((4 - len(x_b64url) % 4) % 4)
    raw_bytes = base64.urlsafe_b64decode(x_b64url + padding)
    if len(raw_bytes) != 32:
        raise ValueError(f"Invalid Ed25519 public key length: {len(raw_bytes)} (expected 32)")
    
    return Ed25519PublicKey.from_public_bytes(raw_bytes)


def verify_receipt_signature(
    public_key: Ed25519PublicKey,
    eval_id: str,
    input_digest: str,
    receipt: Dict[str, Any]
) -> bool:
    """
    Verifies receiptSignature against the canonical JSON envelope:
    {
      "profile": "ga5-mailroom-action-gate/v2",
      "evaluationId": "the commit evaluationId",
      "inputDigest": "the commit inputDigest",
      "receipt": {
        "dossierId":"...", "callId":"...", "action":"...",
        "accepted":true, "proposalDigest":"...", "receiptId":"..."
      }
    }
    """
    sig_b64 = receipt.get("receiptSignature")
    if not sig_b64 or not isinstance(sig_b64, str):
        return False

    # Extract all receipt fields except receiptSignature
    inner_receipt = {k: v for k, v in receipt.items() if k != "receiptSignature"}

    envelope = {
        "profile": PROFILE,
        "evaluationId": eval_id,
        "inputDigest": input_digest,
        "receipt": inner_receipt
    }

    envelope_bytes = canonical_json_bytes(envelope)

    # Base64 decode signature (handle both standard and urlsafe)
    try:
        # Normalize padding
        pad = '=' * ((4 - len(sig_b64) % 4) % 4)
        if '-' in sig_b64 or '_' in sig_b64:
            sig_bytes = base64.urlsafe_b64decode(sig_b64 + pad)
        else:
            sig_bytes = base64.b64decode(sig_b64 + pad)

        public_key.verify(sig_bytes, envelope_bytes)
        return True
    except Exception:
        return False
