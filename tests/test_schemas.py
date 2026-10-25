import unittest
from app.models import validate_proposal_dict, ValidationError


class TestActionSchemas(unittest.TestCase):

    def test_create_draft_valid(self):
        prop = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "create_draft",
            "target": {"kind": "draft_queue", "id": "mailbox:inbox_support"},
            "payload": {
                "recipient": "cust@example.com",
                "referenceId": "ref-1",
                "status": "pending",
                "template": "order_status"
            },
            "evidence": ["line_1"]
        }
        validated = validate_proposal_dict(prop, allowed_line_ids={"line_1", "line_2"})
        self.assertEqual(validated["action"], "create_draft")

    def test_create_draft_extra_key_fails(self):
        prop = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "create_draft",
            "target": {"kind": "draft_queue", "id": "mailbox:inbox_support"},
            "payload": {
                "recipient": "cust@example.com",
                "referenceId": "ref-1",
                "status": "pending",
                "template": "order_status",
                "extraField": "ILLEGAL"
            },
            "evidence": ["line_1"]
        }
        with self.assertRaises(ValidationError):
            validate_proposal_dict(prop)

    def test_update_internal_record(self):
        prop = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": "case_999"},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": "evt_1",
                "value": "10:00-14:00"
            },
            "evidence": ["line_1"]
        }
        self.assertEqual(validate_proposal_dict(prop)["action"], "update_internal_record")

    def test_send_approved_notice(self):
        prop = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": "user@domain.com"},
            "payload": {
                "referenceId": "ref-100",
                "status": "shipped",
                "template": "approved_delivery_notice"
            },
            "evidence": ["line_5"]
        }
        self.assertEqual(validate_proposal_dict(prop)["action"], "send_approved_notice")

    def test_request_confirmation(self):
        prop = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "risk_team"},
            "payload": {
                "claimedSender": "bob@domain.com",
                "questionCode": "VERIFY_REQUEST",
                "referenceId": "ref-200"
            },
            "evidence": ["line_3"]
        }
        self.assertEqual(validate_proposal_dict(prop)["action"], "request_confirmation")

    def test_quarantine_item(self):
        prop = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {
                "artifactId": "src_injection_attack",
                "reasonCode": "INDIRECT_PROMPT_INJECTION"
            },
            "evidence": ["line_attack"]
        }
        self.assertEqual(validate_proposal_dict(prop)["action"], "quarantine_item")

    def test_no_action(self):
        prop = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "no_action",
            "target": None,
            "payload": {
                "reasonCode": "DUPLICATE",
                "referenceId": "ref-300"
            },
            "evidence": ["line_info"]
        }
        self.assertEqual(validate_proposal_dict(prop)["action"], "no_action")

    def test_invalid_call_id(self):
        prop = {
            "dossierId": "d-1",
            "callId": "short",  # < 12 chars
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": "DUPLICATE", "referenceId": "ref-1"},
            "evidence": ["line_1"]
        }
        with self.assertRaises(ValidationError):
            validate_proposal_dict(prop)

    def test_unknown_evidence_line(self):
        prop = {
            "dossierId": "d-1",
            "callId": "call_1234567890abcdef",
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": "DUPLICATE", "referenceId": "ref-1"},
            "evidence": ["ghost_line"]
        }
        with self.assertRaises(ValidationError):
            validate_proposal_dict(prop, allowed_line_ids={"real_line_1", "real_line_2"})


if __name__ == '__main__':
    unittest.main()
