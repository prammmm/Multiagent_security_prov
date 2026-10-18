"""Comprehensive Regression and Safety Unit Tests for Phase 03F Confirmation Runner R9.

Validates the Phase 03F R9 Conservative RAM Pre-Flight Gate:
1. Strict calibration of RAM_PREFLIGHT_THRESHOLD_GB = 7.0 and RAM_MIN_THRESHOLD_GB = 3.0.
2. Unrounded binary GiB boundary precision:
   - 6.999 GiB refuses pre-flight.
   - Exactly 7.0 GiB passes pre-flight.
   - > 7.0 GiB passes pre-flight.
3. Preservation of hard 3.0 GiB monitoring threshold (unchanged at 3.0 GiB).
4. Deterministic refusal behaviour:
   - 6.999 GiB refusal records in audit summary.
   - Zero coordinator instantiation, zero Ollama client invocation, zero trial dispatch.
5. In-trial dip below 3.0 GiB captured and halts sequence post-trial.
6. Intact preservation of output-path isolation and proposal-action attribution integrity.
7. Non-executing validation suite behaviour.

Zero benchmark trials executed. Zero LLM inferences.
"""

import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.run_phase_03f_confirmation_r9 import (
    CONFIRMATION_CONFIGS,
    CONDITIONS,
    MISTRAL_SUBSET_IDS,
    RAM_MIN_THRESHOLD_GB,
    RAM_PREFLIGHT_THRESHOLD_GB,
    DEFAULT_SUMMARY_PATH,
    DEFAULT_TRACES_DIR,
    PROJECT_ROOT,
    ALLOWED_SUMMARY_PATH,
    ALLOWED_TRACES_DIR,
    OutputPathValidationResult,
    resolve_normalized_path,
    validate_output_paths,
    ContinuousRamMonitor,
    get_gpu_telemetry,
    evaluate_ram_headroom,
    classify_malicious_proposal,
    check_malicious_proposal,
    _are_arguments_equal,
    evaluate_injection_exposure,
    evaluate_trial_proposals_and_actions,
    aggregate_trial_gate_decision,
    match_proposals_to_gate_decisions_collection,
    match_proposals_to_actions_collection,
    validate_runner,
    init_summary_file,
    _safe_write_summary,
    run_confirmation_suite,
)
from src.pipeline.schema import EvaluationMode


class TestR9RamThresholdCalibration(unittest.TestCase):
    """Verify threshold constants and unrounded floating-point binary GiB boundaries."""

    def test_threshold_constants_values(self):
        """Req 2: Verify exact threshold values."""
        self.assertEqual(RAM_PREFLIGHT_THRESHOLD_GB, 7.0, "Pre-flight threshold must be exactly 7.0 GB")
        self.assertEqual(RAM_MIN_THRESHOLD_GB, 3.0, "Hard monitoring threshold must remain strictly 3.0 GB")

    def test_preflight_unrounded_boundary_6_999_refusal(self):
        """Req 3: 6.999 GiB available must strictly fail pre-flight threshold."""
        bytes_6_999 = int(6.999 * (1024 ** 3))
        passed, val = evaluate_ram_headroom(bytes_6_999, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertFalse(passed, "6.999 GiB must fail the 7.0 GiB pre-flight threshold")
        self.assertLess(val, 7.0)

        bytes_6_999999 = int(6.999999 * (1024 ** 3))
        passed_sub, val_sub = evaluate_ram_headroom(bytes_6_999999, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertFalse(passed_sub, "6.999999 GiB must fail the 7.0 GiB pre-flight threshold without rounding up")
        self.assertLess(val_sub, 7.0)

    def test_preflight_exact_7_0_gib_passes(self):
        """Req 3: Exactly 7.0 GiB available must pass pre-flight threshold."""
        bytes_7_0 = int(7.00000000 * (1024 ** 3))
        passed, val = evaluate_ram_headroom(bytes_7_0, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertTrue(passed, "Exactly 7.0 GiB must pass the 7.0 GiB pre-flight threshold")
        self.assertGreaterEqual(val, 7.0)

    def test_preflight_more_than_7_0_gib_passes(self):
        """Req 3: More than 7.0 GiB available must pass pre-flight threshold."""
        bytes_7_000001 = int(7.000001 * (1024 ** 3))
        passed_1, val_1 = evaluate_ram_headroom(bytes_7_000001, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertTrue(passed_1, "7.000001 GiB must pass pre-flight threshold")
        self.assertGreater(val_1, 7.0)

        bytes_8_5 = int(8.500000 * (1024 ** 3))
        passed_2, val_2 = evaluate_ram_headroom(bytes_8_5, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertTrue(passed_2, "8.5 GiB must pass pre-flight threshold")
        self.assertGreater(val_2, 7.0)

    def test_hard_3_0_gib_monitoring_threshold_unchanged(self):
        """Req 3: Hard 3.0 GiB monitoring threshold remains unchanged and strictly enforced."""
        bytes_below = int(2.999999 * (1024 ** 3))
        passed_below, val_below = evaluate_ram_headroom(bytes_below, threshold_gb=RAM_MIN_THRESHOLD_GB)
        self.assertFalse(passed_below, "2.999999 GiB must fail the 3.0 GiB monitoring threshold")
        self.assertLess(val_below, 3.0)

        bytes_exact = int(3.00000000 * (1024 ** 3))
        passed_exact, val_exact = evaluate_ram_headroom(bytes_exact, threshold_gb=RAM_MIN_THRESHOLD_GB)
        self.assertTrue(passed_exact, "Exactly 3.0 GiB must pass the 3.0 GiB monitoring threshold")
        self.assertGreaterEqual(val_exact, 3.0)

        bytes_above = int(3.000001 * (1024 ** 3))
        passed_above, val_above = evaluate_ram_headroom(bytes_above, threshold_gb=RAM_MIN_THRESHOLD_GB)
        self.assertTrue(passed_above, "3.000001 GiB must pass the 3.0 GiB monitoring threshold")
        self.assertGreater(val_above, 3.0)


class MockTraceRecord:
    def __init__(self, run_id="test-run-1"):
        self.run_id = run_id
        self.researcher_observations = []
        self.planner_proposals = []
        self.proposals = []
        self.gate_decisions = []
        self.executed_actions = []
        self.injection_payloads = {}
        self.execution_attempted = False
        self.execution_completed = False
        self.environment_mutated = False
        self.utility_success = True
        self.security_breach = False
        self.errors = []


class TestR9PreflightExecutionGuards(unittest.TestCase):
    """Verify that pre-flight refusal blocks coordinator instantiation, Ollama calls, and trial dispatch."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.summary_path = os.path.join(self.tmp_dir, "phase_03f_confirmation_summary.json")
        self.traces_dir = os.path.join(self.tmp_dir, "traces")
        os.makedirs(self.traces_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("scripts.run_phase_03f_confirmation_r9.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    @patch("src.pipeline.ollama_client.OllamaClient")
    def test_preflight_refusal_at_6_999_gib_prevents_coordinator_and_inference(
        self, mock_ollama_client, mock_coordinator, mock_vm, mock_val_paths
    ):
        """Req 3: 6.999 GiB refuses pre-flight: zero coordinator init, zero Ollama calls, trial not dispatched."""
        # Setup mock validation paths
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        # Mock virtual memory to 6.999 GiB
        mock_vm_obj = MagicMock()
        mock_vm_obj.available = int(6.999 * (1024 ** 3))
        mock_vm.return_value = mock_vm_obj

        # Execute confirmation suite
        run_confirmation_suite(
            include_mistral=False,
            summary_path=self.summary_path,
            traces_dir=self.traces_dir,
        )

        # 1. PipelineCoordinator must NOT have been instantiated
        mock_coordinator.assert_not_called()

        # 2. OllamaClient must NOT have been instantiated
        mock_ollama_client.assert_not_called()

        # 3. Summary file must exist and contain the pre-flight refusal audit record
        self.assertTrue(os.path.exists(self.summary_path))
        with open(self.summary_path, "r", encoding="utf-8") as f:
            summary_data = json.load(f)

        self.assertEqual(len(summary_data), 1)
        record = summary_data[0]
        self.assertEqual(record["stopping_reason"], "RAM_INSUFFICIENT_PRE_FLIGHT")
        self.assertLess(record["ram_available_gb_before"], 7.0)
        self.assertEqual(record["ram_preflight_threshold_gb"], 7.0)
        self.assertEqual(record["ram_min_threshold_gb"], 3.0)
        self.assertIn("fell below conservative pre-flight threshold", record["error"])

    @patch("scripts.run_phase_03f_confirmation_r9.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_preflight_pass_at_exact_7_0_gib_instantiates_coordinator_and_runs(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 3: Exactly 7.0 GiB passes pre-flight and dispatches trial."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        mock_vm_obj = MagicMock()
        mock_vm_obj.available = int(7.00000000 * (1024 ** 3))
        mock_vm.return_value = mock_vm_obj

        mock_instance = MagicMock()
        mock_trace = MockTraceRecord("test-run-1")
        mock_instance.run_trial.return_value = mock_trace
        mock_coordinator_cls.return_value = mock_instance

        # Mock one trial run
        with patch("scripts.run_phase_03f_confirmation_r9.CONFIRMATION_CONFIGS", [CONFIRMATION_CONFIGS[0]]):
            with patch("scripts.run_phase_03f_confirmation_r9.CONDITIONS", [CONDITIONS[0]]):
                run_confirmation_suite(
                    include_mistral=False,
                    summary_path=self.summary_path,
                    traces_dir=self.traces_dir,
                )

        # Coordinator was instantiated after passing pre-flight check
        mock_coordinator_cls.assert_called_once()
        mock_instance.run_trial.assert_called_once()

        # Summary records successful execution without RAM stopping reason
        with open(self.summary_path, "r", encoding="utf-8") as f:
            summary_data = json.load(f)
        self.assertEqual(len(summary_data), 1)
        self.assertIsNone(summary_data[0]["stopping_reason"])

    @patch("scripts.run_phase_03f_confirmation_r9.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_in_trial_dip_below_3_0_gib_halts_sequence_post_trial(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 2: Pre-flight passes >= 7.0 GiB, but in-trial dip < 3.0 GiB halts sequence after trial returns."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        mock_vm_obj = MagicMock()
        # Pre-flight returns 7.5 GiB
        mock_vm_obj.available = int(7.5 * (1024 ** 3))
        mock_vm.return_value = mock_vm_obj

        mock_instance = MagicMock()
        mock_trace = MockTraceRecord("test-run-dip")
        mock_instance.run_trial.return_value = mock_trace
        mock_coordinator_cls.return_value = mock_instance

        # Patch ContinuousRamMonitor.stop to return 2.4 GiB dip
        with patch.object(ContinuousRamMonitor, "stop", return_value=2.4000):
            # Offer 2 configs: first should run and halt, second must NOT run
            with patch("scripts.run_phase_03f_confirmation_r9.CONFIRMATION_CONFIGS", CONFIRMATION_CONFIGS[:2]):
                with patch("scripts.run_phase_03f_confirmation_r9.CONDITIONS", [CONDITIONS[0]]):
                    run_confirmation_suite(
                        include_mistral=False,
                        summary_path=self.summary_path,
                        traces_dir=self.traces_dir,
                    )

        # First trial executed
        self.assertEqual(mock_instance.run_trial.call_count, 1)

        # Summary records stopping reason and halted sequence
        with open(self.summary_path, "r", encoding="utf-8") as f:
            summary_data = json.load(f)
        self.assertEqual(len(summary_data), 1)
        self.assertIn("Available RAM fell below 3.0 GB", summary_data[0]["stopping_reason"])


class TestR9PreservedSafeguards(unittest.TestCase):
    """Verify that existing output-path containment, attribution integrity, and static checks remain intact."""

    def test_output_path_traversal_rejection(self):
        """Req 3: Output path validation rejects traversal outside allowed destinations."""
        bad_summary = os.path.join(PROJECT_ROOT, "reports", "..", "secrets.json")
        res = validate_output_paths(bad_summary, ALLOWED_TRACES_DIR)
        self.assertFalse(res.is_valid)

    def test_output_path_reserved_prefix_rejection(self):
        """Req 3: Output path validation protects reserved prefixes."""
        reserved_summary = os.path.join(PROJECT_ROOT, "traces", "summary.json")
        res = validate_output_paths(reserved_summary, ALLOWED_TRACES_DIR)
        self.assertFalse(res.is_valid)

    def test_attribution_identity_conflict_quarantined(self):
        """Req 3: Gate identity conflicts are quarantined and do not leak into Pass 2 signature matches."""
        class MockP:
            def __init__(self, tool, args, pid=None):
                self.tool_name, self.arguments, self.proposal_id = tool, args, pid

        class MockG:
            def __init__(self, tool, args, did=None, pid=None, auth=True):
                self.evaluated_tool, self.evaluated_arguments = tool, args
                self.decision_id, self.proposal_id = did, pid
                self.decision = "ALLOW" if auth else "DENY"
                self.gate_authorized, self.reason = auth, "test"

        p_a = MockP("send_money", {"to": "alice", "amt": 5}, pid="prop-A")
        p_b = MockP("send_money", {"to": "attacker", "amt": 500}, pid="prop-B")
        # Decision 0 references prop-A ID but evaluates Proposal B's content
        g_0 = MockG("send_money", {"to": "attacker", "amt": 500}, did="g-0", pid="prop-A")

        attrs, unclaimed = match_proposals_to_gate_decisions_collection([p_a, p_b], [g_0])
        self.assertFalse(attrs[0]["matched"])
        self.assertEqual(attrs[0]["match_method"], "UNRESOLVED_SHARED_ID_CONTENT_MISMATCH")

        # Proposal B must NOT claim Decision 0 in Pass 2
        self.assertFalse(attrs[1]["matched"])
        self.assertEqual(attrs[1]["match_method"], "UNRESOLVED_NO_GATE_DECISION")
        self.assertEqual(len(unclaimed), 1)
        self.assertTrue(unclaimed[0].get("identity_conflict"))

    def test_static_validation_runner_passes(self):
        """Req 5: validate_runner passes in non-executing mode with zero errors."""
        report = validate_runner(verbose=False)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["errors"]), 0)
        self.assertEqual(report["checks"]["ram_threshold_calibrated"], "PASS")
        self.assertEqual(report["checks"]["ram_guard_precision"], "PASS")


if __name__ == "__main__":
    unittest.main()
