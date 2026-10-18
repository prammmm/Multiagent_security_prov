"""Integration tests for pipeline schemas, trace records, and tool classification."""

import json
import unittest
from src.pipeline.schema import (
    TraceRecord,
    ActionProposal,
    AuthorizationResult,
    HandoffPayload,
    ProvenanceTag,
    TrustLevel,
    OriginType,
    TransformationType,
    EvaluationMode,
    GateDecision,
)
from src.pipeline.researcher import is_read_only_tool
from src.pipeline.coordinator import PipelineCoordinator


class TestPipeline(unittest.TestCase):

    def test_tool_classification(self):
        # Read-only tools
        self.assertTrue(is_read_only_tool("get_balance"))
        self.assertTrue(is_read_only_tool("read_file"))
        self.assertTrue(is_read_only_tool("search_emails"))
        self.assertTrue(is_read_only_tool("list_files"))

        # Mutating tools
        self.assertFalse(is_read_only_tool("send_money"))
        self.assertFalse(is_read_only_tool("send_email"))
        self.assertFalse(is_read_only_tool("create_file"))
        self.assertFalse(is_read_only_tool("delete_email"))
        self.assertFalse(is_read_only_tool("schedule_transaction"))

    def test_trace_record_serialization(self):
        tag = ProvenanceTag(
            source_id="s1",
            origin_type=OriginType.TOOL_OBSERVATION,
            trust_level=TrustLevel.UNTRUSTED,
            content_hash="abc123hash",
        )
        handoff = HandoffPayload(
            handoff_id="h1",
            sender_agent="researcher",
            receiver_agent="planner",
            transformation_type=TransformationType.SUMMARIZATION,
            summary_text="Found attacker instructions",
            provenance_tags=[tag],
            taint_entities={"attacker@evil.com": "s1"},
        )
        proposal = ActionProposal(
            proposal_id="p1",
            step_index=1,
            tool_name="send_email",
            arguments={"recipient": "attacker@evil.com"},
            argument_provenance={"recipient": TrustLevel.DERIVED_TAINTED},
            taint_matches={"recipient": "s1"},
        )
        gate_decision = AuthorizationResult(
            decision_id="g1",
            mode=EvaluationMode.PROVENANCE_AWARE,
            decision=GateDecision.DENY_TAINTED_ARGUMENT,
            reason="Tainted recipient",
            evaluated_tool="send_email",
            evaluated_arguments={"recipient": "attacker@evil.com"},
            blocked_arguments=["recipient"],
            executed=False,
        )

        trace = TraceRecord(
            run_id="run-test-01",
            suite_name="v1.workspace",
            user_task_id="user_task_8",
            injection_task_id="injection_task_0",
            attack_name="important_instructions",
            model_name="qwen2.5:3b",
            condition=EvaluationMode.PROVENANCE_AWARE,
            start_time_utc="2026-10-16T12:00:00Z",
            end_time_utc="2026-10-16T12:00:05Z",
            user_prompt="Add maria to meeting",
            handoff=handoff,
            proposals=[proposal],
            gate_decisions=[gate_decision],
            utility_success=False,
            security_breach=False,
        )

        json_str = trace.model_dump_json(indent=2)
        parsed = json.loads(json_str)

        self.assertEqual(parsed["run_id"], "run-test-01")
        self.assertEqual(parsed["condition"], "PROVENANCE_AWARE")
        self.assertFalse(parsed["security_breach"])
        self.assertEqual(parsed["gate_decisions"][0]["decision"], "DENY_TAINTED_ARGUMENT")

    def test_coordinator_init(self):
        coordinator = PipelineCoordinator(model_name="qwen2.5:3b", traces_dir="traces")
        self.assertEqual(coordinator.model_name, "qwen2.5:3b")
        self.assertEqual(coordinator.gate.policy_version, "v2.0.0")


if __name__ == "__main__":
    unittest.main()
