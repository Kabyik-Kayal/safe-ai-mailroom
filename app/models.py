import re
from typing import Any, Dict, List, Literal, Optional, Set

CALL_ID_REGEX = re.compile(r'^[A-Za-z0-9._:-]{12,128}$')

ALLOWED_ACTIONS = [
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action"
]


class ValidationError(ValueError):
    """Schema validation error compatible with both standard library and pydantic."""
    pass


def validate_dossier_dict(d: Dict[str, Any]) -> Set[str]:
    """Validates a raw dossier dictionary and returns all valid lineIds."""
    if not isinstance(d, dict):
        raise ValidationError("Dossier must be a dictionary")
    
    did = d.get("dossierId")
    if not did or not isinstance(did, str):
        raise ValidationError("Missing or invalid dossierId")

    partition = d.get("partition")
    if partition not in ("stable_core", "fresh_audit"):
        raise ValidationError(f"Invalid partition '{partition}', expected 'stable_core' or 'fresh_audit'")

    sources = d.get("sources")
    if not isinstance(sources, list):
        raise ValidationError("sources must be a list")

    all_line_ids = set()
    for s in sources:
        if not isinstance(s, dict):
            raise ValidationError("source must be a dictionary")
        lines = s.get("lines")
        if not isinstance(lines, list):
            raise ValidationError("source lines must be a list")
        for line in lines:
            if not isinstance(line, dict):
                raise ValidationError("line must be a dictionary")
            lid = line.get("lineId")
            if not lid or not isinstance(lid, str):
                raise ValidationError("Missing lineId in line")
            all_line_ids.add(lid)

    return all_line_ids


def validate_proposal_dict(proposal: Dict[str, Any], allowed_line_ids: Optional[Set[str]] = None) -> Dict[str, Any]:
    """
    Validates a proposal dictionary against exact frozen action schemas:
    1. callId format (12-128 chars, ^[A-Za-z0-9._:-]{12,128}$)
    2. action in ALLOWED_ACTIONS
    3. target & payload matching exact frozen schema with NO extra fields
    4. evidence non-empty list of unique valid lineIds
    """
    if not isinstance(proposal, dict):
        raise ValidationError("Proposal must be a dictionary")

    # 1. callId
    cid = proposal.get("callId")
    if not cid or not isinstance(cid, str) or not CALL_ID_REGEX.match(cid):
        raise ValidationError(f"Invalid callId '{cid}'. Must be 12-128 chars matching ^[A-Za-z0-9._:-]{{12,128}}$")

    # 2. action
    act = proposal.get("action")
    if act not in ALLOWED_ACTIONS:
        raise ValidationError(f"Invalid action '{act}'. Allowed: {ALLOWED_ACTIONS}")

    t = proposal.get("target")
    p = proposal.get("payload")
    if not isinstance(p, dict):
        raise ValidationError("payload must be a dictionary")

    # 3. Exact target & payload validation
    if act == "create_draft":
        if not isinstance(t, dict) or t.get("kind") != "draft_queue" or not str(t.get("id", "")).startswith("mailbox:"):
            raise ValidationError("create_draft target must have kind='draft_queue' and id='mailbox:<mailbox>'")
        expected_keys = {"recipient", "referenceId", "status", "template"}
        if set(p.keys()) != expected_keys:
            raise ValidationError(f"create_draft payload keys must be exactly {expected_keys}, got {set(p.keys())}")
        if p.get("template") != "order_status":
            raise ValidationError("create_draft payload template must be 'order_status'")

    elif act == "update_internal_record":
        if not isinstance(t, dict) or t.get("kind") != "case_record" or not t.get("id"):
            raise ValidationError("update_internal_record target must have kind='case_record' and non-empty id")
        expected_keys = {"field", "sourceEventId", "value"}
        if set(p.keys()) != expected_keys:
            raise ValidationError(f"update_internal_record payload keys must be exactly {expected_keys}, got {set(p.keys())}")
        if p.get("field") != "delivery_window":
            raise ValidationError("update_internal_record payload field must be 'delivery_window'")

    elif act == "send_approved_notice":
        if not isinstance(t, dict) or t.get("kind") != "email" or not t.get("id"):
            raise ValidationError("send_approved_notice target must have kind='email' and non-empty id")
        expected_keys = {"referenceId", "status", "template"}
        if set(p.keys()) != expected_keys:
            raise ValidationError(f"send_approved_notice payload keys must be exactly {expected_keys}, got {set(p.keys())}")
        if p.get("template") != "approved_delivery_notice":
            raise ValidationError("send_approved_notice payload template must be 'approved_delivery_notice'")

    elif act == "request_confirmation":
        if not isinstance(t, dict) or t.get("kind") != "approval_queue" or not t.get("id"):
            raise ValidationError("request_confirmation target must have kind='approval_queue' and non-empty id")
        expected_keys = {"claimedSender", "questionCode", "referenceId"}
        if set(p.keys()) != expected_keys:
            raise ValidationError(f"request_confirmation payload keys must be exactly {expected_keys}, got {set(p.keys())}")
        if p.get("questionCode") != "VERIFY_REQUEST":
            raise ValidationError("request_confirmation payload questionCode must be 'VERIFY_REQUEST'")

    elif act == "quarantine_item":
        if not isinstance(t, dict) or t.get("kind") != "security_queue" or t.get("id") != "mailroom":
            raise ValidationError("quarantine_item target must be kind='security_queue' and id='mailroom'")
        expected_keys = {"artifactId", "reasonCode"}
        if set(p.keys()) != expected_keys:
            raise ValidationError(f"quarantine_item payload keys must be exactly {expected_keys}, got {set(p.keys())}")
        if p.get("reasonCode") != "INDIRECT_PROMPT_INJECTION":
            raise ValidationError("quarantine_item payload reasonCode must be 'INDIRECT_PROMPT_INJECTION'")

    elif act == "no_action":
        if t is not None:
            raise ValidationError("no_action target must be null")
        expected_keys = {"reasonCode", "referenceId"}
        if set(p.keys()) != expected_keys:
            raise ValidationError(f"no_action payload keys must be exactly {expected_keys}, got {set(p.keys())}")
        allowed_reasons = {"ALREADY_COMPLETED", "DUPLICATE", "INFORMATIONAL"}
        if p.get("reasonCode") not in allowed_reasons:
            raise ValidationError(f"no_action reasonCode must be one of {allowed_reasons}")

    # 4. Evidence validation
    evidence = proposal.get("evidence")
    if not isinstance(evidence, list) or len(evidence) == 0:
        raise ValidationError("evidence must be a non-empty list of lineIds")
    if len(evidence) != len(set(evidence)):
        raise ValidationError("evidence must not contain duplicate lineIds")

    if allowed_line_ids is not None:
        for eid in evidence:
            if eid not in allowed_line_ids:
                raise ValidationError(f"Evidence lineId '{eid}' not present in dossier")

    return proposal


# Optional Pydantic bridge if installed
try:
    from pydantic import BaseModel, model_validator

    class Line(BaseModel):
        model_config = {"extra": "allow"}
        lineId: str
        text: str

    class Source(BaseModel):
        model_config = {"extra": "allow"}
        sourceId: Optional[str] = None
        artifactId: Optional[str] = None
        kind: Optional[str] = None
        provenance: Optional[str] = None
        title: Optional[str] = ""
        lines: List[Line] = []

    class Dossier(BaseModel):
        model_config = {"extra": "allow"}
        dossierId: str
        partition: Literal["stable_core", "fresh_audit"]
        receivedAt: Optional[str] = None
        mailbox: Optional[str] = "inbox"
        objective: Optional[str] = ""
        sources: List[Source] = []

        def all_line_ids(self) -> Set[str]:
            return {line.lineId for s in self.sources for line in s.lines}

    class Target(BaseModel):
        model_config = {"extra": "allow"}
        kind: str
        id: str

    class Proposal(BaseModel):
        model_config = {"extra": "allow"}
        dossierId: str
        callId: str
        action: str
        target: Optional[Target] = None
        payload: Dict[str, Any]
        evidence: List[str]

        @model_validator(mode='after')
        def validate_schema(self):
            validate_proposal_dict(self.model_dump())
            return self

except ImportError:
    # Graceful fallback classes for environments where pydantic is being installed
    class Dossier:
        def __init__(self, **kwargs):
            self.data = kwargs
            self.dossierId = kwargs.get("dossierId")
            self.partition = kwargs.get("partition")
            self.receivedAt = kwargs.get("receivedAt")
            self.mailbox = kwargs.get("mailbox")
            self.objective = kwargs.get("objective")
            self.sources = kwargs.get("sources", [])
            validate_dossier_dict(kwargs)

        def all_line_ids(self) -> Set[str]:
            return validate_dossier_dict(self.data)

        def model_dump(self) -> Dict[str, Any]:
            return self.data

    class Proposal:
        def __init__(self, **kwargs):
            self.data = kwargs
            self.dossierId = kwargs.get("dossierId")
            self.callId = kwargs.get("callId")
            self.action = kwargs.get("action")
            self.target = kwargs.get("target")
            self.payload = kwargs.get("payload", {})
            self.evidence = kwargs.get("evidence", [])
            validate_proposal_dict(kwargs)

        def model_dump(self) -> Dict[str, Any]:
            return {
                "dossierId": self.dossierId,
                "callId": self.callId,
                "action": self.action,
                "target": self.target.model_dump() if hasattr(self.target, "model_dump") else self.target,
                "payload": self.payload,
                "evidence": self.evidence
            }

    class Target:
        def __init__(self, kind: str, id: str):
            self.kind = kind
            self.id = id

        def model_dump(self) -> Dict[str, str]:
            return {"kind": self.kind, "id": self.id}
