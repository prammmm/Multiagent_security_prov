"""Comprehensive Regression and Safety Unit Tests for Phase 03F Confirmation Runner R10.

Validates the Phase 03F R10 Candidate (Dual-Stage 7.0 GiB Pre-Flight RAM Gate, Strictly Qwen-Only):
1. Calibration of RAM_PREFLIGHT_THRESHOLD_GB = 7.0 and RAM_MIN_THRESHOLD_GB = 3.0.
2. Dual-stage pre-flight RAM checks:
   - Stage 1 initial pre-flight check at 7.0 GiB (refuses at 6.999 GiB before coordinator setup or telemetry).
   - Stage 2 final pre-dispatch check at 7.0 GiB (refuses if RAM drops below 7.0 GiB after telemetry & coordinator setup).
3. Test simulating RAM at 7.5 GiB during initial pre-flight and below 7.0 GiB at final dispatch check:
   - Verifies zero trial dispatches (run_trial is NEVER called).
   - Verifies refusal is recorded in the audit summary.
4. Strictly Qwen-Only enforcement:
   - run_confirmation_suite(include_mistral=True) raises ValueError.
   - CLI invocation with --include-mistral triggers parser error and exits.
5. In-trial dip below 3.0 GiB captured by monitor and halts sequence post-trial.
6. Intact preservation of output-path isolation, attribution integrity, and non-executing validation.

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

from scripts.run_phase_03f_confirmation_r10 import (
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
    main,
)
from src.pipeline.schema import EvaluationMode


class MockTraceRecord:
    """Deterministic, JSON-serializable synthetic TraceRecord for testing."""
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


class TestR10RamThresholdCalibration(unittest.TestCase):
    """Verify threshold constants and unrounded floating-point binary GiB boundaries."""

    def test_threshold_constants_values(self):
        """Req 1 & 5: Verify exact threshold values."""
        self.assertEqual(RAM_PREFLIGHT_THRESHOLD_GB, 7.0, "Pre-flight threshold must be exactly 7.0 GB")
        self.assertEqual(RAM_MIN_THRESHOLD_GB, 3.0, "Hard monitoring threshold must remain strictly 3.0 GB")

    def test_preflight_unrounded_boundary_6_999_refusal(self):
        """Req 1: 6.999 GiB available must strictly fail pre-flight threshold."""
        bytes_6_999 = int(6.999 * (1024 ** 3))
        passed, val = evaluate_ram_headroom(bytes_6_999, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertFalse(passed, "6.999 GiB must fail the 7.0 GiB pre-flight threshold")
        self.assertLess(val, 7.0)

        bytes_6_999999 = int(6.999999 * (1024 ** 3))
        passed_sub, val_sub = evaluate_ram_headroom(bytes_6_999999, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertFalse(passed_sub, "6.999999 GiB must fail the 7.0 GiB pre-flight threshold without rounding up")
        self.assertLess(val_sub, 7.0)

    def test_preflight_exact_7_0_gib_passes(self):
        """Req 1: Exactly 7.0 GiB available must pass pre-flight threshold."""
        bytes_7_0 = int(7.00000000 * (1024 ** 3))
        passed, val = evaluate_ram_headroom(bytes_7_0, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertTrue(passed, "Exactly 7.0 GiB must pass the 7.0 GiB pre-flight threshold")
        self.assertGreaterEqual(val, 7.0)

    def test_preflight_more_than_7_0_gib_passes(self):
        """Req 1: More than 7.0 GiB available must pass pre-flight threshold."""
        bytes_7_000001 = int(7.000001 * (1024 ** 3))
        passed_1, val_1 = evaluate_ram_headroom(bytes_7_000001, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertTrue(passed_1, "7.000001 GiB must pass pre-flight threshold")
        self.assertGreater(val_1, 7.0)

        bytes_8_5 = int(8.500000 * (1024 ** 3))
        passed_2, val_2 = evaluate_ram_headroom(bytes_8_5, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertTrue(passed_2, "8.5 GiB must pass pre-flight threshold")
        self.assertGreater(val_2, 7.0)

    def test_hard_3_0_gib_monitoring_threshold_unchanged(self):
        """Req 5: Hard 3.0 GiB monitoring threshold remains unchanged and strictly enforced."""
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


class TestR10DualStagePreflightGuards(unittest.TestCase):
    """Verify dual-stage pre-flight checks and refusal guarantees."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.summary_path = os.path.join(self.tmp_dir, "phase_03f_confirmation_summary.json")
        self.traces_dir = os.path.join(self.tmp_dir, "traces")
        os.makedirs(self.traces_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("scripts.run_phase_03f_confirmation_r10.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    @patch("src.pipeline.ollama_client.OllamaClient")
    def test_stage1_preflight_refusal_at_6_999_gib_prevents_coordinator_init(
        self, mock_ollama_client, mock_coordinator, mock_vm, mock_val_paths
    ):
        """Req 1 & 2: Stage 1 refusal at 6.999 GiB blocks coordinator init, Ollama, and trial dispatch."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        mock_vm_obj = MagicMock()
        mock_vm_obj.available = int(6.999 * (1024 ** 3))
        mock_vm.return_value = mock_vm_obj

        run_confirmation_suite(
            include_mistral=False,
            summary_path=self.summary_path,
            traces_dir=self.traces_dir,
        )

        # 1. PipelineCoordinator must NOT have been instantiated
        mock_coordinator.assert_not_called()
        mock_ollama_client.assert_not_called()

        # 2. Summary file must contain Stage 1 refusal record
        self.assertTrue(os.path.exists(self.summary_path))
        with open(self.summary_path, "r", encoding="utf-8") as f:
            summary_data = json.load(f)

        self.assertEqual(len(summary_data), 1)
        record = summary_data[0]
        self.assertEqual(record["stopping_reason"], "RAM_INSUFFICIENT_PRE_FLIGHT_INITIAL")
        self.assertLess(record["ram_available_gb_initial"], 7.0)
        self.assertIn("initial pre-flight check", record["error"])

    @patch("scripts.run_phase_03f_confirmation_r10.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_stage2_preflight_refusal_at_final_dispatch_check_prevents_trial_run(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 4: RAM at 7.5 GiB during initial pre-flight and 6.8 GiB at final dispatch check -> ZERO trial dispatches."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        # Simulate psutil.virtual_memory:
        # Call 1 (Stage 1 initial check): 7.5 GiB (passes)
        # Call 2 (Stage 2 pre-dispatch check): 6.8 GiB (fails < 7.0 GiB)
        vm_7_5 = MagicMock()
        vm_7_5.available = int(7.5 * (1024 ** 3))
        vm_6_8 = MagicMock()
        vm_6_8.available = int(6.8 * (1024 ** 3))
        def vm_side_effect():
            if mock_vm.call_count == 1:
                return vm_7_5
            return vm_6_8
        mock_vm.side_effect = vm_side_effect

        mock_instance = MagicMock()
        mock_coordinator_cls.return_value = mock_instance

        run_confirmation_suite(
            include_mistral=False,
            summary_path=self.summary_path,
            traces_dir=self.traces_dir,
        )

        # Coordinator was initialized after Stage 1 passed...
        mock_coordinator_cls.assert_called_once()

        # CRITICAL ASSERTION: run_trial() must NEVER have been called!
        mock_instance.run_trial.assert_not_called()

        # Summary records Stage 2 pre-dispatch refusal with both telemetry values
        self.assertTrue(os.path.exists(self.summary_path))
        with open(self.summary_path, "r", encoding="utf-8") as f:
            summary_data = json.load(f)

        self.assertEqual(len(summary_data), 1)
        record = summary_data[0]
        self.assertEqual(record["stopping_reason"], "RAM_INSUFFICIENT_PRE_FLIGHT_DISPATCH")
        self.assertGreaterEqual(record["ram_available_gb_initial"], 7.0)
        self.assertLess(record["ram_available_gb_dispatch"], 7.0)
        self.assertEqual(record["ram_preflight_threshold_gb"], 7.0)
        self.assertIn("immediately before trial dispatch", record["error"])

    @patch("scripts.run_phase_03f_confirmation_r10.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_both_stages_pass_executes_trial(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 2: When both Stage 1 and Stage 2 pre-flight checks pass >= 7.0 GiB, trial is dispatched."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        mock_vm_obj = MagicMock()
        mock_vm_obj.available = int(7.2 * (1024 ** 3))
        mock_vm.return_value = mock_vm_obj

        mock_instance = MagicMock()
        mock_trace = MockTraceRecord("test-run-success")
        mock_instance.run_trial.return_value = mock_trace
        mock_coordinator_cls.return_value = mock_instance

        with patch("scripts.run_phase_03f_confirmation_r10.CONFIRMATION_CONFIGS", [CONFIRMATION_CONFIGS[0]]):
            with patch("scripts.run_phase_03f_confirmation_r10.CONDITIONS", [CONDITIONS[0]]):
                run_confirmation_suite(
                    include_mistral=False,
                    summary_path=self.summary_path,
                    traces_dir=self.traces_dir,
                )

        mock_coordinator_cls.assert_called_once()
        mock_instance.run_trial.assert_called_once()

        with open(self.summary_path, "r", encoding="utf-8") as f:
            summary_data = json.load(f)
        self.assertEqual(len(summary_data), 1)
        self.assertIsNone(summary_data[0]["stopping_reason"])
        self.assertGreaterEqual(summary_data[0]["ram_available_gb_initial"], 7.0)
        self.assertGreaterEqual(summary_data[0]["ram_available_gb_dispatch"], 7.0)

    @patch("scripts.run_phase_03f_confirmation_r10.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_in_trial_dip_below_3_0_gib_halts_sequence_post_trial(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 5: In-trial dip below 3.0 GiB halts sequence after trial returns."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        mock_vm_obj = MagicMock()
        mock_vm_obj.available = int(7.5 * (1024 ** 3))
        mock_vm.return_value = mock_vm_obj

        mock_instance = MagicMock()
        mock_trace = MockTraceRecord("test-run-dip")
        mock_instance.run_trial.return_value = mock_trace
        mock_coordinator_cls.return_value = mock_instance

        # Patch ContinuousRamMonitor.start and stop to simulate 2.4 GiB dip without leaving background thread running
        with patch.object(ContinuousRamMonitor, "start"), \
             patch.object(ContinuousRamMonitor, "stop", return_value=2.4000):
            with patch("scripts.run_phase_03f_confirmation_r10.CONFIRMATION_CONFIGS", CONFIRMATION_CONFIGS[:2]):
                with patch("scripts.run_phase_03f_confirmation_r10.CONDITIONS", [CONDITIONS[0]]):
                    run_confirmation_suite(
                        include_mistral=False,
                        summary_path=self.summary_path,
                        traces_dir=self.traces_dir,
                    )

        # First trial ran and returned
        self.assertEqual(mock_instance.run_trial.call_count, 1)

        # Summary records stopping reason and halts subsequent trial
        with open(self.summary_path, "r", encoding="utf-8") as f:
            summary_data = json.load(f)
        self.assertEqual(len(summary_data), 1)
        self.assertIn("Available RAM fell below 3.0 GB", summary_data[0]["stopping_reason"])


class TestR10StrictlyQwenOnlyEnforcement(unittest.TestCase):
    """Verify that Mistral Nemo 12B cross-model subset is rejected at CLI and API levels."""

    def test_run_confirmation_suite_rejects_include_mistral(self):
        """Req 3: Execution function strictly rejects include_mistral=True with ValueError."""
        with self.assertRaises(ValueError) as ctx:
            run_confirmation_suite(include_mistral=True)
        self.assertIn("strictly Qwen-only", str(ctx.exception))
        self.assertIn("Mistral Nemo 12B cross-model subset is permanently disallowed", str(ctx.exception))

    def test_cli_parser_rejects_include_mistral(self):
        """Req 3: CLI parser exits with error when --include-mistral is passed."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r10.py", "--include-mistral"]):
            with self.assertRaises(SystemExit):
                main()

    def test_validate_runner_reports_strictly_qwen_only_matrix(self):
        """Req 3 & 5: validate_runner reports exactly 36 Qwen runs and 0 Mistral runs."""
        report = validate_runner(verbose=False)
        self.assertEqual(report["status"], "PASS")
        matrix_check = report["checks"]["matrix_dimensions"]
        self.assertEqual(matrix_check["qwen_runs"], 36)
        self.assertEqual(matrix_check["mistral_runs"], 0)
        self.assertEqual(matrix_check["total_planned_runs"], 36)
        self.assertTrue(matrix_check["strictly_qwen_only"])


class TestR10PreservedSafeguards(unittest.TestCase):
    """Verify output-path isolation, attribution integrity, and non-executing default mode."""

    def test_output_path_traversal_rejection(self):
        """Req 5: Output path validation rejects traversal outside allowed destinations."""
        bad_summary = os.path.join(PROJECT_ROOT, "reports", "..", "secrets.json")
        res = validate_output_paths(bad_summary, ALLOWED_TRACES_DIR)
        self.assertFalse(res.is_valid)

    def test_attribution_identity_conflict_quarantined(self):
        """Req 5: Gate identity conflicts are quarantined and do not leak into Pass 2 signature matches."""
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
        g_0 = MockG("send_money", {"to": "attacker", "amt": 500}, did="g-0", pid="prop-A")

        attrs, unclaimed = match_proposals_to_gate_decisions_collection([p_a, p_b], [g_0])
        self.assertFalse(attrs[0]["matched"])
        self.assertEqual(attrs[0]["match_method"], "UNRESOLVED_SHARED_ID_CONTENT_MISMATCH")

        self.assertFalse(attrs[1]["matched"])
        self.assertEqual(attrs[1]["match_method"], "UNRESOLVED_NO_GATE_DECISION")
        self.assertEqual(len(unclaimed), 1)
        self.assertTrue(unclaimed[0].get("identity_conflict"))


if __name__ == "__main__":
    unittest.main()
