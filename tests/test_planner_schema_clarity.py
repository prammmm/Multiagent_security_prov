"""Focused Unit Tests for Planner Tool-Schema Clarity and Parameter Formatting.

Verifies:
1. Required fields are marked with ' (required)'.
2. Optional fields are marked with ' (optional)' when present in tool schemas.
3. Existing tool descriptions retain their names, types, and documentation.
4. Planning instructions prohibit invented required values and instruct the no-action fallback.
5. Generic prompt builder does not hardcode attack-specific artifacts, fallbacks, or candidates.
6. PlannerAgent.plan() executes cleanly with mocked LLM client and builds prompt with schema markers.
"""

import sys
import os
import unittest
from typing import Optional, List, Dict, Any
from unittest.mock import MagicMock
from pydantic import BaseModel, Field

# Ensure project root is available in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentdojo.task_suite.load_suites import get_suite
from src.pipeline.planner import PlannerAgent
from src.pipeline.provenance import ProvenanceTracker
from src.pipeline.schema import HandoffPayload, TransformationType, TrustLevel


class TestPlannerToolSchemaClarity(unittest.TestCase):
    """Test suite verifying generic parameter requirement labeling in tool descriptions."""

    @classmethod
    def setUpClass(cls):
        cls.banking_suite = get_suite("v1", "banking")
        cls.workspace_suite = get_suite("v1", "workspace")

    def test_required_fields_marked_correctly_banking_send_money(self):
        """Verify send_money parameters are all identified as (required)."""
        send_money_tool = next(t for t in self.banking_suite.tools if t.name == "send_money")
        desc = PlannerAgent.format_tool_descriptions([send_money_tool])

        self.assertIn("- send_money(", desc)
        self.assertIn("recipient: str (required)", desc)
        self.assertIn("amount: float (required)", desc)
        self.assertIn("subject: str (required)", desc)
        self.assertIn("date: str (required)", desc)
        self.assertIn(": Sends a transaction to the recipient.", desc)

    def test_optional_fields_marked_correctly_banking_update_scheduled_transaction(self):
        """Verify update_scheduled_transaction distinguishes required 'id' from optional fields."""
        update_tool = next(t for t in self.banking_suite.tools if t.name == "update_scheduled_transaction")
        desc = PlannerAgent.format_tool_descriptions([update_tool])

        self.assertIn("- update_scheduled_transaction(", desc)
        self.assertIn("id: int (required)", desc)
        self.assertIn("recipient: str | None (optional)", desc)
        self.assertIn("amount: float | None (optional)", desc)
        self.assertIn("subject: str | None (optional)", desc)
        self.assertIn("date: str | None (optional)", desc)
        self.assertIn("recurring: bool | None (optional)", desc)

    def test_optional_fields_marked_correctly_banking_get_most_recent_transactions(self):
        """Verify get_most_recent_transactions identifies optional parameter n."""
        recent_tool = next(t for t in self.banking_suite.tools if t.name == "get_most_recent_transactions")
        desc = PlannerAgent.format_tool_descriptions([recent_tool])

        self.assertIn("- get_most_recent_transactions(n: int (optional)):", desc)

    def test_workspace_calendar_and_email_schemas(self):
        """Verify create_calendar_event, add_calendar_event_participants, and send_email."""
        create_event = next(t for t in self.workspace_suite.tools if t.name == "create_calendar_event")
        add_part = next(t for t in self.workspace_suite.tools if t.name == "add_calendar_event_participants")
        send_email = next(t for t in self.workspace_suite.tools if t.name == "send_email")

        desc = PlannerAgent.format_tool_descriptions([create_event, add_part, send_email])

        # create_calendar_event
        self.assertIn("title: str (required)", desc)
        self.assertIn("start_time: str (required)", desc)
        self.assertIn("end_time: str (required)", desc)
        self.assertIn("description: str (optional)", desc)
        self.assertIn("participants: list[str] | None (optional)", desc)

        # add_calendar_event_participants
        self.assertIn("event_id: str (required)", desc)
        self.assertIn("participants: list[str] (required)", desc)

        # send_email
        self.assertIn("recipients: list[str] (required)", desc)
        self.assertIn("subject: str (required)", desc)
        self.assertIn("body: str (required)", desc)
        self.assertIn("attachments: list[dict] | None (optional)", desc)

    def test_synthetic_pydantic_model_schema_formatting(self):
        """Verify format_tool_descriptions on custom Pydantic schema with both required and optional fields."""
        class MockParams(BaseModel):
            must_have: str
            must_have_num: float
            optional_with_default: int = 10
            optional_with_none: Optional[str] = None

        class MockTool:
            name = "mock_tool"
            description = "A synthetic mock tool for unit testing.\nSecond line doc."
            parameters = MockParams

        desc = PlannerAgent.format_tool_descriptions([MockTool()])
        self.assertIn("- mock_tool(", desc)
        self.assertIn("must_have: str (required)", desc)
        self.assertIn("must_have_num: float (required)", desc)
        self.assertIn("optional_with_default: int (optional)", desc)
        self.assertIn("optional_with_none: Optional[str] (optional)", desc)
        self.assertIn("): A synthetic mock tool for unit testing.", desc)

    def test_synthetic_properties_schema_formatting(self):
        """Verify format_tool_descriptions on dictionary/properties-style parameters."""
        class MockPropertiesSchema:
            properties = {"alpha": {}, "beta": {}, "gamma": {}}
            required = ["alpha", "gamma"]

        class MockDictTool:
            name = "dict_tool"
            description = "Dict tool description."
            parameters = MockPropertiesSchema()

        desc = PlannerAgent.format_tool_descriptions([MockDictTool()])
        self.assertIn("alpha (required)", desc)
        self.assertIn("beta (optional)", desc)
        self.assertIn("gamma (required)", desc)

    def test_planning_instructions_prohibit_invented_required_values(self):
        """Verify prompt builder instructs mandatory argument compliance and forbids hallucinated fallbacks."""
        planner = PlannerAgent(model_name="qwen2.5:7b-instruct")
        handoff = HandoffPayload(
            handoff_id="h-test",
            sender_agent="researcher",
            receiver_agent="planner",
            transformation_type=TransformationType.SUMMARIZATION,
            summary_text="Bill observed with missing amount.",
            provenance_tags=[],
        )
        send_money_tool = next(t for t in self.banking_suite.tools if t.name == "send_money")

        prompt = planner.build_prompt(
            user_prompt="Please pay the bill",
            handoff=handoff,
            available_tools=[send_money_tool],
        )

        # Core required-argument instruction
        self.assertIn(
            "Every argument marked as (required) in the chosen tool's schema must be supplied.",
            prompt,
        )
        self.assertIn(
            "If required information is missing, do not invent or arbitrarily default a value",
            prompt,
        )
        self.assertIn(
            'return the established no-action result ("tool": "none")',
            prompt,
        )

        # Prohibit synthetic fallbacks or hardcoding in generic prompt
        self.assertNotIn("0.01", prompt)
        self.assertNotIn("BK-DSC-02", prompt)
        self.assertNotIn("US133000000121212121212", prompt)

    def test_mocked_plan_executes_with_schema_formatting(self):
        """Verify PlannerAgent.plan() generates prompt with schema clarity and parses response without inference."""
        mock_client = MagicMock()
        mock_client.generate.return_value = {
            "response": '{"tool": "none", "reasoning": "Missing mandatory amount parameter."}',
            "client_duration_seconds": 0.05,
        }

        planner = PlannerAgent(model_name="qwen2.5:7b-instruct", client=mock_client)
        handoff = HandoffPayload(
            handoff_id="h-test-2",
            sender_agent="researcher",
            receiver_agent="planner",
            transformation_type=TransformationType.SUMMARIZATION,
            summary_text="Missing amount in bill.",
            provenance_tags=[],
        )
        tracker = ProvenanceTracker(user_goal="Pay bill")
        send_money_tool = next(t for t in self.banking_suite.tools if t.name == "send_money")

        proposal = planner.plan(
            user_prompt="Pay bill",
            handoff=handoff,
            available_tools=[send_money_tool],
            provenance_tracker=tracker,
        )

        self.assertEqual(proposal.tool_name, "none")
        self.assertEqual(proposal.planner_reasoning, "Missing mandatory amount parameter.")
        self.assertEqual(len(planner.telemetry), 1)

        # Confirm the prompt actually sent to the client had the formatted (required) schema
        generated_prompt = mock_client.generate.call_args[1]["prompt"]
        self.assertIn("amount: float (required)", generated_prompt)
        self.assertIn("recipient: str (required)", generated_prompt)


if __name__ == "__main__":
    unittest.main()
