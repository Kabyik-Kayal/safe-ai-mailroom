import sqlite3
import json
import os
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

DB_PATH = os.environ.get("MAILROOM_DB_PATH", "mailroom.db")


def get_db():
    db_path = os.environ.get("MAILROOM_DB_PATH", "mailroom.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Evaluation state table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                input_digest TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                verifier_jwk TEXT NOT NULL,
                proposals_json TEXT NOT NULL,
                propose_response_json TEXT NOT NULL,
                commit_response_json TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # 2. Dossier content-addressable cache
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dossier_cache (
                content_hash TEXT PRIMARY KEY,
                dossier_id TEXT NOT NULL,
                call_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_json TEXT,
                payload_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                proposal_digest TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        
        conn.commit()


def save_dossier_proposal(content_hash: str, proposal: Dict[str, Any], proposal_digest: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO dossier_cache (
                content_hash, dossier_id, call_id, action,
                target_json, payload_json, evidence_json, proposal_digest, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            content_hash,
            proposal["dossierId"],
            proposal["callId"],
            proposal["action"],
            json.dumps(proposal.get("target")),
            json.dumps(proposal["payload"]),
            json.dumps(proposal["evidence"]),
            proposal_digest,
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()


def get_cached_proposal(content_hash: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM dossier_cache WHERE content_hash = ?", (content_hash,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "dossierId": row["dossier_id"],
            "callId": row["call_id"],
            "action": row["action"],
            "target": json.loads(row["target_json"]) if row["target_json"] else None,
            "payload": json.loads(row["payload_json"]),
            "evidence": json.loads(row["evidence_json"]),
            "proposalDigest": row["proposal_digest"]
        }


def get_evaluation(eval_id: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evaluations WHERE evaluation_id = ?", (eval_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)


def save_propose_evaluation(
    eval_id: str,
    input_digest: str,
    request_hash: str,
    verifier_jwk: Dict[str, Any],
    proposals: List[Dict[str, Any]],
    propose_response: Dict[str, Any]
):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO evaluations (
                evaluation_id, input_digest, request_hash, verifier_jwk,
                proposals_json, propose_response_json, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            eval_id,
            input_digest,
            request_hash,
            json.dumps(verifier_jwk),
            json.dumps(proposals),
            json.dumps(propose_response),
            "awaiting_receipts",
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()


def save_commit_evaluation(eval_id: str, commit_response: Dict[str, Any]):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE evaluations
            SET commit_response_json = ?, status = 'completed'
            WHERE evaluation_id = ?
        """, (json.dumps(commit_response), eval_id))
        conn.commit()
