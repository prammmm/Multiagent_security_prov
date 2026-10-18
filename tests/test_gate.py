"""Unit tests for Deterministic Authorization Boundary."""

import unittest
from src.pipeline.schema import (
    ActionProposal,
    EvaluationMode,
    GateDecision,
    TrustLevel,
)
from src.pipeline.gate import DeterministicAuthorizationBoundary


class TestGate(unittest.TestCase):

    def test_gate_baseline_mode(self):
        gate = DeterministicAuthorizationBoundary()
        proposal = ActionProposal(
            proposal_id="p1",
            step_index=1,
            tool_name="malicious_tool",
            arguments={"target": "http://evil.com"},
            argument_provenance={"target": TrustLevel.DERIVED_TAINTED},
        )

        result = gate.evaluate(
            proposal=proposal,
            user_goal="Do something benign",
            allowed_tools={"legit_tool"},
            condition=EvaluationMode.BASELINE,
        )

        self.assertEqual(result.decision, GateDecision.ALLOW)
        self.assertTrue(result.executed)
        self.assertIn("Baseline condition", result.reason)

    def test_gate_conventional_mode_tool_whitelist(self):
        gate = DeterministicAuthorizationBoundary()
        allowed = {"send_money", "get_balance"}

        # Unauthorized tool
        prop_unauth = ActionProposal(
            proposal_id="p2",
            step_index=1,
            tool_name="delete_database",
            arguments={},
        )
        res_unauth = gate.evaluate(
            proposal=prop_unauth,
            user_goal="Check balance",
            allowed_tools=allowed,
            condition=EvaluationMode.CONVENTIONAL,
        )
        self.assertEqual(res_unauth.decision, GateDecision.DENY_UNAUTHORIZED_TOOL)
        self.assertFalse(res_unauth.executed)

        # Whitelisted tool, but containing tainted arguments (Conventional is BLIND to arguments!)
        prop_tainted = ActionProposal(
            proposal_id="p3",
            step_index=1,
            tool_name="send_money",
            arguments={"recipient": "US133000000121212121212", "amount": 100},
            argument_provenance={"recipient": TrustLevel.DERIVED_TAINTED},
            taint_matches={"recipient": "obs-1"},
        )
        res_tainted = gate.evaluate(
            proposal=prop_tainted,
            user_goal="Pay bill",
            allowed_tools=allowed,
            condition=EvaluationMode.CONVENTIONAL,
        )
        # Conventional ALLOWS because send_money is in whitelist
        self.assertEqual(res_tainted.decision, GateDecision.ALLOW)
        self.assertTrue(res_tainted.executed)

    def test_gate_provenance_aware_mode(self):
        gate = DeterministicAuthorizationBoundary()
        allowed = {"send_money", "get_balance"}

        # Case A: Whitelisted tool, clean arguments -> ALLOW
        prop_clean = ActionProposal(
            proposal_id="p4",
            step_index=1,
            tool_name="send_money",
            arguments={"recipient": "UK12345678901234567890", "amount": 50},
            argument_provenance={"recipient": TrustLevel.TRUSTED, "amount": TrustLevel.TRUSTED},
        )
        res_clean = gate.evaluate(
            proposal=prop_clean,
            user_goal="Pay bill UK12345678901234567890",
            allowed_tools=allowed,
            condition=EvaluationMode.PROVENANCE_AWARE,
        )
        self.assertEqual(res_clean.decision, GateDecision.ALLOW)
        self.assertTrue(res_clean.executed)

        # Case B: Whitelisted tool, tainted argument -> DENY_TAINTED_ARGUMENT
        prop_tainted = ActionProposal(
            proposal_id="p5",
            step_index=1,
            tool_name="send_money",
            arguments={"recipient": "US133000000121212121212", "amount": 100},
            argument_provenance={"recipient": TrustLevel.DERIVED_TAINTED, "amount": TrustLevel.TRUSTED},
            taint_matches={"recipient": "obs-evil-memo"},
        )
        res_tainted = gate.evaluate(
            proposal=prop_tainted,
            user_goal="Pay bill UK12345678901234567890",
            allowed_tools=allowed,
            condition=EvaluationMode.PROVENANCE_AWARE,
        )
        self.assertEqual(res_tainted.decision, GateDecision.DENY_TAINTED_ARGUMENT)
        self.assertFalse(res_tainted.executed)
        self.assertIn("recipient", res_tainted.blocked_arguments)

        # Case C: Whitelisted tool, uncertain sensitive slot not in user goal -> DENY_TAINTED_ARGUMENT
        prop_uncertain = ActionProposal(
            proposal_id="p6",
            step_index=1,
            tool_name="send_money",
            arguments={"recipient": "FR99999999999999999999", "amount": 25},
            argument_provenance={"recipient": TrustLevel.UNCERTAIN, "amount": TrustLevel.TRUSTED},
        )
        res_uncertain = gate.evaluate(
            proposal=prop_uncertain,
            user_goal="Pay bill UK12345678901234567890",
            allowed_tools=allowed,
            condition=EvaluationMode.PROVENANCE_AWARE,
        )
        self.assertEqual(res_uncertain.decision, GateDecision.DENY_TAINTED_ARGUMENT)
        self.assertFalse(res_uncertain.executed)
        self.assertIn("recipient", res_uncertain.blocked_arguments)


if __name__ == "__main__":
    unittest.main()
