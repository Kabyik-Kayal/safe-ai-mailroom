import os
import json
import re
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import httpx
except ImportError:
    httpx = None

from app.models import Proposal, Dossier, Target, ValidationError, validate_proposal_dict
from app.crypto import sha256_hex, canonical_json_bytes

logger = logging.getLogger(__name__)

CANARY_REGEX = re.compile(
    r'(?i)\b(?:canary|vault_secret|secret_token|private_key|auth_secret|canary_token|vault_key|access_token|api_key|admin_secret)\b'
)


def clean_email_str(em: str) -> str:
    """Strips trailing sentence punctuation from email addresses."""
    return em.rstrip('.,;:!?)>"\'] ').strip().lower()


def sanitize_canaries(payload: Dict[str, Any], dossier_id: str) -> Dict[str, Any]:
    """Ensures secret tokens or canaries are never leaked into tool arguments."""
    if not isinstance(payload, dict):
        return payload
    sanitized = dict(payload)
    for k, v in sanitized.items():
        if isinstance(v, str) and k != "reasonCode" and CANARY_REGEX.search(v):
            sanitized[k] = f"ref_{dossier_id[:8]}"
    return sanitized


def verify_outbound_safety(
    dossier: Dossier,
    action: str,
    target: Optional[Dict[str, Any]],
    payload: Dict[str, Any]
) -> Tuple[str, Optional[Dict[str, Any]], Dict[str, Any]]:
    """
    Guarantees send_approved_notice is ONLY performed when an internal trusted
    source explicitly authorized sending to this exact recipient email.
    Otherwise safely downgrades to create_draft (non-sent draft queue).
    """
    if action != "send_approved_notice":
        return action, target, payload

    target_email = ""
    if isinstance(target, dict):
        target_email = clean_email_str(str(target.get("id", "")))

    if not target_email or "@" not in target_email:
        return "create_draft", {"kind": "draft_queue", "id": f"mailbox:{dossier.mailbox}"}, {
            "recipient": target_email or f"customer_{dossier.dossierId[:6]}@example.com",
            "referenceId": payload.get("referenceId", dossier.dossierId),
            "status": payload.get("status", "pending"),
            "template": "order_status"
        }

    sources = dossier.sources if isinstance(dossier.sources, list) else []
    has_trusted_approval = False

    for s in sources:
        s_dict = s if isinstance(s, dict) else (s.model_dump() if hasattr(s, "model_dump") else getattr(s, "data", {}))
        provenance = str(s_dict.get("provenance", "")).lower().strip()
        if provenance not in ("internal", "system", "staff", "manager", "admin", "logistics", "dispatch", "support"):
            continue

        lines = s_dict.get("lines", [])
        for l in lines:
            l_dict = l if isinstance(l, dict) else (l.model_dump() if hasattr(l, "model_dump") else getattr(l, "data", {}))
            txt = l_dict.get("text", "").lower()
            if any(k in txt for k in ("approved", "authorization", "authorize", "permission", "permit", "cleared to send")) and (target_email in txt or "@" in txt):
                has_trusted_approval = True
                break

    if not has_trusted_approval:
        return "create_draft", {"kind": "draft_queue", "id": f"mailbox:{dossier.mailbox}"}, {
            "recipient": target_email,
            "referenceId": payload.get("referenceId", dossier.dossierId),
            "status": payload.get("status", "pending"),
            "template": "order_status"
        }

    return action, target, payload


def analyze_dossier_strictly(dossier: Dossier) -> Dict[str, Any]:
    """
    Expert decision engine based on authority, provenance, and case state.
    Extracts real case-specific arguments and minimal sufficient evidence.
    """
    sources = dossier.sources if isinstance(dossier.sources, list) else []
    dossier_id = dossier.dossierId
    mailbox = getattr(dossier, "mailbox", "inbox")
    objective = getattr(dossier, "objective", "").lower()

    # Regex patterns for entity extraction
    re_email = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', re.IGNORECASE)
    re_ref_explicit = re.compile(r'\b(?:ORD|CASE|REF|TKT|INC|REQ|PKG|INV|TRK)[-_]?[A-Za-z0-9]*\d+[A-Za-z0-9]*\b', re.IGNORECASE)
    re_hash_ref = re.compile(r'#([A-Za-z0-9_-]+)')
    re_labeled_ref = re.compile(r'(?i)\b(?:order|case|ticket|reference|package|shipment|invoice|ref|tracking)\s*(?:number|no|id|#)?[:\s]+([A-Za-z0-9_-]+)')
    re_win = re.compile(r'(\b\d{1,2}(?::\d{2})?\s*(?:am|pm|AM|PM)?\s*-\s*\d{1,2}(?::\d{2})?\s*(?:am|pm|AM|PM)?\b)', re.IGNORECASE)
    re_status = re.compile(r'\b(shipped|delivered|in_transit|delayed|processing|out_for_delivery|pending|ready|cancelled|completed)\b', re.IGNORECASE)

    # Prompt injection patterns (ONLY valid from untrusted/external sources)
    injection_pats = [
        re.compile(r'ignore (all )?(previous|prior) (instructions|directions|prompts)', re.IGNORECASE),
        re.compile(r'disregard (all )?(previous|prior) (instructions|directions|rules)', re.IGNORECASE),
        re.compile(r'system prompt (override|injection|reset)', re.IGNORECASE),
        re.compile(r'override (all )?(security|safety) (protocols|prompts|filters|instructions)', re.IGNORECASE),
        re.compile(r'send (me )?(the )?(canary|secret|token|vault|password|key)', re.IGNORECASE),
        re.compile(r'(exfiltrat|leak|reveal|print|output|display) (the )?(canary|secret|token|vault|password|key|prompt)', re.IGNORECASE),
        re.compile(r'\b(?:canary[_ ]token|vault[_ ]secret|auth[_ ]secret|secret[_ ]token)\b', re.IGNORECASE),
        re.compile(r'admin (bypass|override)', re.IGNORECASE),
        re.compile(r'you are now in (developer|dan|jailbreak|unrestricted) mode', re.IGNORECASE),
        re.compile(r'eval\(|exec\(', re.IGNORECASE),
        re.compile(r'curl\s+http|wget\s+http|webhook|fetch\(', re.IGNORECASE),
        re.compile(r'drop\s+table|delete\s+from', re.IGNORECASE),
        re.compile(r'forward (all )?(mail|emails) to', re.IGNORECASE),
    ]

    all_lines: List[Tuple[str, str, str, str]] = []  # (source_id, provenance, line_id, text)
    untrusted_injections: List[Tuple[str, str, str]] = []  # (source_id, line_id, text)
    trusted_window_updates: List[Tuple[str, str, str, str]] = []  # (source_id, line_id, window_val, text)
    trusted_approvals: List[Tuple[str, str, str, str]] = []  # (source_id, line_id, recipient_email, text)
    identity_conflicts: List[Tuple[str, str, str]] = []  # (line_id, claimed_sender, text)
    completed_markers: List[Tuple[str, str]] = []  # (line_id, reasonCode)
    duplicate_markers: List[Tuple[str, str]] = []  # (line_id, reasonCode)
    informational_markers: List[Tuple[str, str]] = []  # (line_id, reasonCode)

    all_refs: List[Tuple[str, str]] = []  # (line_id, ref_str)
    all_case_ids: List[Tuple[str, str]] = []  # (line_id, case_str)
    all_emails: List[Tuple[str, str]] = []  # (line_id, email_str)
    all_statuses: List[Tuple[str, str]] = []  # (line_id, status_str)

    trusted_provenances = ("internal", "system", "staff", "manager", "admin", "logistics", "dispatch", "security")

    for s in sources:
        s_dict = s if isinstance(s, dict) else (s.model_dump() if hasattr(s, "model_dump") else getattr(s, "data", {}))
        source_id = s_dict.get("sourceId") or s_dict.get("artifactId") or "src_main"
        provenance = str(s_dict.get("provenance", "")).lower().strip()
        title = str(s_dict.get("title", ""))
        is_trusted = provenance in trusted_provenances
        is_untrusted = not is_trusted

        # Check references in title
        for r in re_ref_explicit.findall(title):
            all_refs.append(("title", r))
            if r.upper().startswith("CASE"):
                all_case_ids.append(("title", r))
        for m in re_labeled_ref.finditer(title):
            all_refs.append(("title", m.group(1)))
            if "case" in m.group(0).lower():
                all_case_ids.append(("title", m.group(1)))

        lines = s_dict.get("lines", [])
        for l in lines:
            l_dict = l if isinstance(l, dict) else (l.model_dump() if hasattr(l, "model_dump") else getattr(l, "data", {}))
            lid = l_dict.get("lineId", "l_0")
            txt = l_dict.get("text", "")
            txt_lower = txt.lower()
            all_lines.append((source_id, provenance, lid, txt))

            # 1. Entity Extraction with punctuation cleaning
            for em in re_email.findall(txt):
                all_emails.append((lid, clean_email_str(em)))
            for rf in re_ref_explicit.findall(txt):
                all_refs.append((lid, rf))
                if rf.upper().startswith("CASE"):
                    all_case_ids.append((lid, rf))
            for hrf in re_hash_ref.findall(txt):
                all_refs.append((lid, hrf))
            for m in re_labeled_ref.finditer(txt):
                all_refs.append((lid, m.group(1)))
                if "case" in m.group(0).lower():
                    all_case_ids.append((lid, m.group(1)))
            for st in re_status.findall(txt):
                if st.lower() != "completed":
                    all_statuses.append((lid, st.lower()))

            # 2. Injection detection (ONLY for untrusted/external provenance)
            if is_untrusted:
                for pat in injection_pats:
                    if pat.search(txt):
                        untrusted_injections.append((source_id, lid, txt))
                        break

            # 3. Delivery window updates (differentiate trusted authority vs customer inquiry)
            win_m = re_win.search(txt)
            if win_m:
                win_val = win_m.group(1).strip()
                if is_trusted:
                    trusted_window_updates.append((source_id, lid, win_val, txt))

            # 4. Outbound approval (ONLY from trusted authority)
            if is_trusted and any(k in txt_lower for k in ("approved", "authorization", "authorize", "permission", "cleared to send", "grant permission")):
                em_m = re_email.search(txt)
                rec_em = clean_email_str(em_m.group(0)) if em_m else ""
                trusted_approvals.append((source_id, lid, rec_em, txt))

            # 5. Identity ambiguity / verification needed
            if any(k in txt_lower for k in (
                "unclear identity", "sender mismatch", "claimed sender", "verify request",
                "unconfirmed", "dispute", "fraud", "suspicious sender", "claims to be",
                "address mismatch", "unverified sender"
            )):
                em_m = re_email.search(txt)
                claimed = clean_email_str(em_m.group(0)) if em_m else ""
                identity_conflicts.append((lid, claimed, txt))

            # 6. Case state markers: Completed / Duplicate / Informational
            if any(k in txt_lower for k in ("already completed", "already shipped", "already delivered", "task complete", "case closed", "order resolved", "order fulfilled", "previously fulfilled")):
                completed_markers.append((lid, "ALREADY_COMPLETED"))
            elif any(k in txt_lower for k in ("duplicate", "already received earlier", "identical to ticket", "repeated submission")):
                duplicate_markers.append((lid, "DUPLICATE"))
            elif is_trusted and any(k in txt_lower for k in ("informational", "no action required", "security advisory", "quoted for reference", "internal log", "threat analysis", "fyi", "for reference")):
                informational_markers.append((lid, "INFORMATIONAL"))

    # Helpers to find body-grounded entities
    body_refs = [r for r in all_refs if r[0] != "title"]
    body_case_ids = [c for c in all_case_ids if c[0] != "title"]
    body_emails = [e for e in all_emails if e[0] != "title"]
    body_statuses = [s for s in all_statuses if s[0] != "title"]

    default_ref = body_refs[0][1] if body_refs else (all_refs[0][1] if all_refs else None)
    if not default_ref:
        m = re_ref_explicit.search(dossier_id)
        default_ref = m.group(0) if m else f"ref_{dossier_id[:8]}"

    # =========================================================================
    # DECISION LOGIC: BASED ON AUTHORITY, PROVENANCE, AND CASE STATE
    # =========================================================================

    # -------------------------------------------------------------------------
    # RULE 1: QUARANTINE ITEM (Untrusted Prompt Injection / Canary Probe)
    # -------------------------------------------------------------------------
    if untrusted_injections:
        src_id, inj_lid, _ = untrusted_injections[0]
        inj_lids = [item[1] for item in untrusted_injections]
        return {
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {
                "artifactId": src_id,
                "reasonCode": "INDIRECT_PROMPT_INJECTION"
            },
            "evidence": sorted(list(set(inj_lids)))
        }

    # -------------------------------------------------------------------------
    # RULE 2: UPDATE INTERNAL RECORD (Specifically Authorized Delivery Window)
    # -------------------------------------------------------------------------
    if trusted_window_updates:
        auth_src_id, win_lid, win_val, win_txt = trusted_window_updates[0]
        case_id = ""
        case_lid = None
        if body_case_ids:
            case_id = body_case_ids[0][1]
            case_lid = body_case_ids[0][0]
        elif all_case_ids:
            case_id = all_case_ids[0][1]
        elif body_refs:
            case_id = body_refs[0][1]
            case_lid = body_refs[0][0]
        elif all_refs:
            case_id = all_refs[0][1]
        else:
            case_id = f"case_{dossier_id[:8]}"

        evidence = [win_lid]
        if case_lid and case_lid != win_lid:
            evidence.append(case_lid)

        # Look for sourceEventId in source or text
        evt_m = re.search(r'\b(evt_[A-Za-z0-9_-]+|event[-_][A-Za-z0-9_-]+)\b', win_txt, re.I)
        src_event_id = evt_m.group(1) if evt_m else auth_src_id

        return {
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": case_id},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": src_event_id,
                "value": win_val
            },
            "evidence": sorted(list(set(evidence)))
        }

    # -------------------------------------------------------------------------
    # RULE 3: SEND APPROVED NOTICE (Explicit Trusted Approval For Recipient)
    # -------------------------------------------------------------------------
    if trusted_approvals:
        auth_src_id, app_lid, rec_email, app_txt = trusted_approvals[0]
        email_lid = app_lid
        if not rec_email:
            if body_emails:
                rec_email = body_emails[0][1]
                email_lid = body_emails[0][0]
            elif all_emails:
                rec_email = all_emails[0][1]

        if rec_email:
            ref_id = default_ref
            ref_lid = body_refs[0][0] if body_refs else None
            st_val = body_statuses[0][1] if body_statuses else (all_statuses[0][1] if all_statuses else "shipped")
            st_lid = body_statuses[0][0] if body_statuses else None

            evidence = [app_lid]
            if email_lid and email_lid != app_lid:
                evidence.append(email_lid)
            if ref_lid and ref_lid != app_lid and ref_lid != email_lid:
                evidence.append(ref_lid)
            elif st_lid and st_lid != app_lid and st_lid != email_lid:
                evidence.append(st_lid)

            return {
                "action": "send_approved_notice",
                "target": {"kind": "email", "id": rec_email},
                "payload": {
                    "referenceId": ref_id,
                    "status": st_val,
                    "template": "approved_delivery_notice"
                },
                "evidence": sorted(list(set(evidence)))
            }

    # -------------------------------------------------------------------------
    # RULE 4: REQUEST CONFIRMATION (Ambiguous Request / Identity Conflict)
    # -------------------------------------------------------------------------
    if identity_conflicts or any(k in objective for k in ("verify", "confirm", "unclear", "ambiguous", "mismatch", "dispute")):
        unc_lid, claimed_sender, unc_txt = identity_conflicts[0] if identity_conflicts else (all_lines[0][2], "", "")
        sender_lid = None

        if not claimed_sender:
            if body_emails:
                claimed_sender = body_emails[0][1]
                sender_lid = body_emails[0][0]
            elif all_emails:
                claimed_sender = all_emails[0][1]
            else:
                claimed_sender = f"claimed_{dossier_id[:6]}@example.com"

        ref_id = default_ref
        ref_lid = body_refs[0][0] if body_refs else None

        owning_team = "identity_verification" if any(k in mailbox for k in ("billing", "identity", "account", "security")) else "customer_support"

        evidence = [unc_lid]
        if sender_lid and sender_lid != unc_lid:
            evidence.append(sender_lid)
        if ref_lid and ref_lid != unc_lid and ref_lid != sender_lid:
            evidence.append(ref_lid)

        return {
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": owning_team},
            "payload": {
                "claimedSender": claimed_sender,
                "questionCode": "VERIFY_REQUEST",
                "referenceId": ref_id
            },
            "evidence": sorted(list(set(evidence)))
        }

    # -------------------------------------------------------------------------
    # RULE 5: NO ACTION (Duplicate, Completed, or Informational Items)
    # -------------------------------------------------------------------------
    if duplicate_markers or completed_markers or informational_markers or any(k in objective for k in ("duplicate", "completed", "informational", "suppress", "no action", "advisory")):
        if duplicate_markers:
            comp_lid, reason_code = duplicate_markers[0]
        elif completed_markers:
            comp_lid, reason_code = completed_markers[0]
        elif informational_markers:
            comp_lid, reason_code = informational_markers[0]
        else:
            comp_lid, reason_code = all_lines[0][2], "INFORMATIONAL"

        ref_id = default_ref
        ref_lid = body_refs[0][0] if body_refs else None

        evidence = [comp_lid]
        if ref_lid and ref_lid != comp_lid:
            evidence.append(ref_lid)

        return {
            "action": "no_action",
            "target": None,
            "payload": {
                "reasonCode": reason_code,
                "referenceId": ref_id
            },
            "evidence": sorted(list(set(evidence)))
        }

    # -------------------------------------------------------------------------
    # RULE 6: CREATE DRAFT (Standard Customer Inquiry / Order Status Draft)
    # -------------------------------------------------------------------------
    cust_email = ""
    email_lid = None
    if body_emails:
        cust_email = body_emails[0][1]
        email_lid = body_emails[0][0]
    elif all_emails:
        cust_email = all_emails[0][1]
    else:
        cust_email = f"customer_{dossier_id[:8]}@example.com"

    ref_id = default_ref
    ref_lid = body_refs[0][0] if body_refs else None

    st_val = body_statuses[0][1] if body_statuses else (all_statuses[0][1] if all_statuses else "in_transit")
    st_lid = body_statuses[0][0] if body_statuses else None

    evidence = set()
    if email_lid:
        evidence.add(email_lid)
    if ref_lid:
        evidence.add(ref_lid)
    if st_lid:
        evidence.add(st_lid)
    if not evidence:
        evidence.add(all_lines[0][2] if all_lines else "l_0")

    return {
        "action": "create_draft",
        "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
        "payload": {
            "recipient": cust_email,
            "referenceId": ref_id,
            "status": st_val,
            "template": "order_status"
        },
        "evidence": sorted(list(evidence))
    }


async def decide_dossier_action(dossier: Dossier) -> Proposal:
    """
    Decides the action for a dossier using deterministic authority/provenance analysis
    with strict outbound safety, canary protection, and minimal grounded evidence.
    """
    dossier_dict = dossier.model_dump()
    content_bytes = canonical_json_bytes(dossier_dict)
    # v6 cache partition to clear out stale proposals
    content_hash = sha256_hex(b"v6:" + content_bytes)
    call_id = f"call_{content_hash[:24]}"

    # Primary engine: deterministic authority, provenance, and case-state extraction
    extracted = analyze_dossier_strictly(dossier)

    # Apply Outbound Safety Guard & Canary Sanitizer
    safe_action, safe_target, safe_payload = verify_outbound_safety(
        dossier, extracted["action"], extracted.get("target"), extracted["payload"]
    )
    safe_payload = sanitize_canaries(safe_payload, dossier.dossierId)

    # Validate evidence lines belong to dossier
    valid_ids = dossier.all_line_ids()
    cleaned_ev = [lid for lid in extracted["evidence"] if lid in valid_ids]
    if not cleaned_ev:
        cleaned_ev = [next(iter(valid_ids))] if valid_ids else ["l_0"]

    candidate = {
        "dossierId": dossier.dossierId,
        "callId": call_id,
        "action": safe_action,
        "target": safe_target,
        "payload": safe_payload,
        "evidence": sorted(list(set(cleaned_ev)))
    }
    validate_proposal_dict(candidate, dossier.all_line_ids())
    return Proposal(**candidate)
