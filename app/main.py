import json
import logging
import asyncio
from typing import Any, Dict, List

try:
    from fastapi import FastAPI, Request, Response, status
    from fastapi.responses import JSONResponse
except ImportError:
    class FastAPI:
        def __init__(self, **kwargs):
            self.routes = []
        def on_event(self, event):
            def decorator(f):
                return f
            return decorator
        def get(self, *paths):
            def decorator(f):
                return f
            return decorator
        def post(self, *paths):
            def decorator(f):
                return f
            return decorator

    class JSONResponse:
        def __init__(self, status_code: int, content: Any):
            self.status_code = status_code
            self.content = content
            self.body = json.dumps(content).encode('utf-8')

    class status:
        HTTP_200_OK = 200
        HTTP_400_BAD_REQUEST = 400
        HTTP_404_NOT_FOUND = 404
        HTTP_409_CONFLICT = 409
        HTTP_413_REQUEST_ENTITY_TOO_LARGE = 413
        HTTP_422_UNPROCESSABLE_ENTITY = 422
        HTTP_500_INTERNAL_SERVER_ERROR = 500

    class Request:
        pass

from app.crypto import (
    PROFILE,
    canonical_json_bytes,
    sha256_hex,
    compute_input_digest,
    compute_proposal_digest,
    jwk_to_ed25519_public_key,
    verify_receipt_signature
)
from app.models import Dossier, Proposal, ValidationError
from app.storage import (
    init_db,
    get_evaluation,
    save_propose_evaluation,
    save_commit_evaluation,
    get_cached_proposal,
    save_dossier_proposal
)
from app.ai_engine import decide_dossier_action

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mailroom")

app = FastAPI(title="Safe AI Mailroom Agent", version="2.0.0")

# Initialize database on startup
@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/healthz")
@app.get("/health")
def health_check():
    return {"status": "ok", "service": "mailroom-agent"}


@app.get("/status")
def diagnostic_status():
    import os
    groq_key = os.environ.get("GROQ_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    return {
        "status": "ok",
        "ai_provider": os.environ.get("AI_PROVIDER", "unset"),
        "groq_key_configured": bool(groq_key and len(groq_key) > 5),
        "groq_model": os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b"),
        "gemini_key_configured": bool(gemini_key and len(gemini_key) > 5),
        "gemini_model": os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"),
        "openai_key_configured": bool(openai_key and len(openai_key) > 5)
    }


@app.post("/")
@app.post("/mailroom")
async def mailroom_gateway(request: Request):
    """
    Unified public HTTPS endpoint handling both 'propose' and 'commit' operations.
    Supports root path '/' and '/mailroom'.
    """
    # 1. Enforce 512 KiB payload limit
    raw_body = await request.body()
    if len(raw_body) > 512 * 1024:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"error": "Request body exceeds 512 KiB limit"}
        )

    # 2. Parse JSON
    try:
        data = json.loads(raw_body.decode('utf-8'))
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Malformed JSON payload"}
        )

    if not isinstance(data, dict):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Payload must be a JSON object"}
        )

    # 3. Profile verification
    profile = data.get("profile")
    if profile != PROFILE:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": f"Invalid profile. Expected '{PROFILE}', got '{profile}'"}
        )

    operation = data.get("operation")
    if operation == "propose":
        return await handle_propose(data, raw_body)
    elif operation == "commit":
        return await handle_commit(data, raw_body)
    else:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": f"Invalid operation: {operation}"}
        )


async def handle_propose(data: Dict[str, Any], raw_body: bytes) -> JSONResponse:
    eval_id = data.get("evaluationId")
    if not eval_id or not isinstance(eval_id, str):
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"error": "Missing or invalid evaluationId"})

    verifier = data.get("receiptVerifier")
    if not verifier or not isinstance(verifier, dict):
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"error": "Missing receiptVerifier"})

    jwk = verifier.get("publicKeyJwk")
    if not jwk or not isinstance(jwk, dict):
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"error": "Missing publicKeyJwk"})

    try:
        # Validate that the JWK can be parsed
        jwk_to_ed25519_public_key(jwk)
    except Exception as e:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"error": f"Invalid Ed25519 JWK: {e}"})

    dossiers_raw = data.get("dossiers")
    if not isinstance(dossiers_raw, list) or len(dossiers_raw) == 0:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"error": "dossiers must be a non-empty list"})

    # Check for duplicate dossier IDs
    dossier_ids = set()
    for d in dossiers_raw:
        did = d.get("dossierId") if isinstance(d, dict) else None
        if not did:
            return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"error": "dossier missing dossierId"})
        if did in dossier_ids:
            return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"error": f"Duplicate dossierId '{did}'"})
        dossier_ids.add(did)

    # Compute inputDigest over canonical UTF-8 bytes of dossiers
    input_digest = compute_input_digest(dossiers_raw)
    request_hash = sha256_hex(canonical_json_bytes(data))

    # Check for existing evaluationId (Replay vs Conflict)
    existing_eval = get_evaluation(eval_id)
    if existing_eval:
        if existing_eval["request_hash"] == request_hash:
            # Exact replay: return cached response
            cached_resp = json.loads(existing_eval["propose_response_json"])
            return JSONResponse(status_code=status.HTTP_200_OK, content=cached_resp)
        else:
            # Same evaluationId with changed content -> HTTP 409 Conflict
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={"error": "evaluationId already exists with different request content"}
            )

    # Process dossiers concurrently (with a concurrency semaphore)
    sem = asyncio.Semaphore(15)

    async def evaluate_single_dossier(d_raw):
        content_hash = sha256_hex(b"v4:" + canonical_json_bytes(d_raw))
        cached_prop = get_cached_proposal(content_hash)
        did = d_raw.get("dossierId")

        if cached_prop:
            return {
                "dossierId": did,
                "callId": cached_prop["callId"],
                "action": cached_prop["action"],
                "target": cached_prop["target"],
                "payload": cached_prop["payload"],
                "evidence": cached_prop["evidence"]
            }

        dossier_obj = Dossier(**d_raw)
        async with sem:
            proposal_model = await decide_dossier_action(dossier_obj)
        proposal_dict = proposal_model.model_dump()
        proposal_digest = compute_proposal_digest(proposal_dict)
        save_dossier_proposal(content_hash, proposal_dict, proposal_digest)
        return proposal_dict

    try:
        proposals = await asyncio.gather(*(evaluate_single_dossier(d) for d in dossiers_raw))
    except ValidationError as ve:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"error": f"Invalid dossier schema: {ve}"})

    # Prepare final propose response
    propose_response = {
        "profile": PROFILE,
        "evaluationId": eval_id,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals
    }

    # Persist state
    save_propose_evaluation(
        eval_id=eval_id,
        input_digest=input_digest,
        request_hash=request_hash,
        verifier_jwk=jwk,
        proposals=proposals,
        propose_response=propose_response
    )

    return JSONResponse(status_code=status.HTTP_200_OK, content=propose_response)


async def handle_commit(data: Dict[str, Any], raw_body: bytes) -> JSONResponse:
    eval_id = data.get("evaluationId")
    if not eval_id or not isinstance(eval_id, str):
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "Missing or invalid evaluationId"})

    input_digest = data.get("inputDigest")
    if not input_digest or not isinstance(input_digest, str):
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "Missing or invalid inputDigest"})

    receipts = data.get("receipts")
    if not isinstance(receipts, list):
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "receipts must be a list"})

    # Retrieve evaluation
    eval_record = get_evaluation(eval_id)
    if not eval_record:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": f"Unknown evaluationId '{eval_id}'"})

    # Check inputDigest match
    if eval_record["input_digest"] != input_digest:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": f"inputDigest mismatch for evaluationId '{eval_id}'"}
        )

    commit_req_hash = sha256_hex(canonical_json_bytes(data))

    # Check for exact replay of commit vs conflict
    if eval_record["status"] == "completed" and eval_record.get("commit_response_json"):
        if eval_record.get("commit_request_hash") == commit_req_hash:
            cached_commit = json.loads(eval_record["commit_response_json"])
            return JSONResponse(status_code=status.HTTP_200_OK, content=cached_commit)
        else:
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={"error": f"EvaluationId '{eval_id}' already completed with different commit payload"}
            )

    # Load stored public key JWK
    try:
        jwk = json.loads(eval_record["verifier_jwk"])
        public_key = jwk_to_ed25519_public_key(jwk)
    except Exception as e:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"error": f"Failed to load verifier key: {e}"})

    # Load persisted proposals
    stored_proposals = json.loads(eval_record["proposals_json"])
    proposal_map = {p["dossierId"]: p for p in stored_proposals}

    if len(receipts) != len(stored_proposals):
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": f"Receipt count {len(receipts)} does not match proposal count {len(stored_proposals)}"})

    seen_receipt_dossiers = set()
    outcomes = []

    # Verify all receipts atomically before recording effects
    for r in receipts:
        if not isinstance(r, dict):
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "Each receipt must be an object"})

        did = r.get("dossierId")
        cid = r.get("callId")
        act = r.get("action")
        pdigest = r.get("proposalDigest")
        accepted = r.get("accepted")
        rid = r.get("receiptId")
        sig = r.get("receiptSignature")

        if not all([did, cid, act, pdigest, rid, sig]) or accepted is None:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "Missing required field in receipt"})

        if did in seen_receipt_dossiers:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": f"Duplicate receipt for dossier '{did}'"})
        seen_receipt_dossiers.add(did)

        # Check proposal match
        orig_prop = proposal_map.get(did)
        if not orig_prop:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": f"Receipt for unknown dossierId '{did}'"})

        if orig_prop["callId"] != cid:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": f"callId mismatch for dossierId '{did}'"})

        if orig_prop["action"] != act:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": f"action mismatch for dossierId '{did}'"})

        expected_pdigest = compute_proposal_digest(orig_prop)
        if expected_pdigest != pdigest:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": f"proposalDigest mismatch for dossierId '{did}'"})

        # Cryptographic Ed25519 signature verification
        is_valid = verify_receipt_signature(
            public_key=public_key,
            eval_id=eval_id,
            input_digest=input_digest,
            receipt=r
        )
        if not is_valid:
            logger.warning(f"Signature verification FAILED for receipt {rid} (dossier {did})")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": f"Invalid cryptographic signature for receiptId '{rid}'"}
            )

        # Determine execution outcome
        outcome_status = "executed" if accepted is True else "rejected"
        outcomes.append({
            "dossierId": did,
            "callId": cid,
            "action": act,
            "proposalDigest": pdigest,
            "receiptId": rid,
            "status": outcome_status
        })

    # Prepare completed response
    commit_response = {
        "profile": PROFILE,
        "evaluationId": eval_id,
        "status": "completed",
        "inputDigest": input_digest,
        "outcomes": outcomes
    }

    # Persist terminal state
    save_commit_evaluation(eval_id, commit_req_hash, commit_response)

    return JSONResponse(status_code=status.HTTP_200_OK, content=commit_response)
