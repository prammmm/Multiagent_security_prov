"""Comprehensive Regression and Safety Unit Tests for Phase 03F Confirmation Runner R11.

Validates the Phase 03F R11 Candidate:
1. API-Level Execution Authorization Gate:
   - run_confirmation_suite(execution_authorized=False) raises PermissionError.
   - Unauthorized invocation guarantees ZERO trial dispatches (run_trial is NEVER called).
   - Default CLI invocation remains non-executing validation.
2. Strictly Qwen-Only enforcement across all exposed boundaries:
   - run_confirmation_suite(execution_authorized=True, include_mistral=True) raises ValueError.
   - CLI invocation with --include-mistral triggers parser error and exits.
   - Matrix dimension check verifies 36 Qwen runs and 0 Mistral runs.
3. Fail-Closed Resource Monitor Behavior:
   - Telemetry query failure at Stage 1 records RESOURCE_MONITOR_UNAVAILABLE and halts before trial dispatch.
   - Telemetry query failure at Stage 2 records RESOURCE_MONITOR_UNAVAILABLE and halts before trial dispatch.
   - Failure during ContinuousRamMonitor.start() records RESOURCE_MONITOR_UNAVAILABLE and halts before trial dispatch.
4. Dual-Stage 7.0 GiB Pre-Flight RAM Guards:
   - Stage 1 initial check refuses at 6.999 GiB before coordinator init.
   - Stage 2 pre-dispatch check refuses if RAM drops below 7.0 GiB (e.g. 7.5 GiB -> 6.8 GiB) with ZERO trial dispatches.
   - Both stages passing with execution_authorized=True dispatches trial.
5. In-trial dip below 3.0 GiB captured by monitor and halts sequence post-trial.
6. Execution Safety Status:
   - Explicitly verifies EXECUTION_SAFETY_STATUS == "NOT SAFE TO EXECUTE".
   - Verifies technical limitation documentation regarding Windows out-of-process Ollama inference.
7. Preservation of output-path isolation and proposal-to-gate attribution integrity.

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

from scripts.run_phase_03f_confirmation_r11 import (
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
    EXECUTION_SAFETY_STATUS,
    SAFETY_LIMITATION_DOCUMENTATION,
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


class TestR11RamThresholdCalibration(unittest.TestCase):
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


class TestR11ApiAuthorizationEnforcement(unittest.TestCase):
    """Verify that execution authorization is strictly enforced at the API boundary."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.summary_path = os.path.join(self.tmp_dir, "phase_03f_confirmation_summary.json")
        self.traces_dir = os.path.join(self.tmp_dir, "traces")
        os.makedirs(self.traces_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_unauthorized_call_raises_permission_error(self):
        """Req 3: Direct call without execution_authorized=True raises PermissionError."""
        with self.assertRaises(PermissionError) as ctx:
            run_confirmation_suite(
                execution_authorized=False,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )
        self.assertIn("Explicit execution authorization is required", str(ctx.exception))

    @patch("scripts.run_phase_03f_confirmation_r11.validate_output_paths")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_unauthorized_call_never_dispatches_trial_or_inits_coordinator(
        self, mock_coordinator_cls, mock_val_paths
    ):
        """Req 3: Unauthorized call guarantees ZERO coordinator inits and ZERO trial dispatches."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        with self.assertRaises(PermissionError):
            run_confirmation_suite(
                execution_authorized=False,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )

        mock_coordinator_cls.assert_not_called()
        self.assertFalse(os.path.exists(self.summary_path))

    def test_default_cli_invocation_remains_non_executing(self):
        """Req 3: Default CLI invocation (no --execute-confirmation) invokes validate_runner only."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r11.py"]):
            with patch("scripts.run_phase_03f_confirmation_r11.validate_runner") as mock_validate:
                mock_validate.return_value = {"status": "PASS", "errors": []}
                with self.assertRaises(SystemExit) as exit_ctx:
                    main()
                self.assertEqual(exit_ctx.exception.code, 0)
                mock_validate.assert_called_once()

    def test_default_cli_invocation_runs_validation_end_to_end(self):
        """Req 3: Unpatched default CLI invocation passes validation and exits cleanly."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r11.py"]):
            with self.assertRaises(SystemExit) as exit_ctx:
                main()
            self.assertEqual(exit_ctx.exception.code, 0)

    @patch("scripts.run_phase_03f_confirmation_r11.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_api_authorized_flag_allows_execution_when_preconditions_met(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 3: Only explicitly authorized execution with valid preconditions reaches trial dispatch."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        vm_mock = MagicMock()
        vm_mock.available = int(7.5 * (1024 ** 3))
        mock_vm.return_value = vm_mock

        mock_instance = MagicMock()
        mock_trace = MockTraceRecord("test-run-auth-pass")
        mock_instance.run_trial.return_value = mock_trace
        mock_coordinator_cls.return_value = mock_instance

        with patch.object(ContinuousRamMonitor, "start"), \
             patch.object(ContinuousRamMonitor, "stop", return_value=7.4):
            with patch("scripts.run_phase_03f_confirmation_r11.CONFIRMATION_CONFIGS", [CONFIRMATION_CONFIGS[0]]):
                with patch("scripts.run_phase_03f_confirmation_r11.CONDITIONS", [CONDITIONS[0]]):
                    run_confirmation_suite(
                        execution_authorized=True,
                        include_mistral=False,
                        summary_path=self.summary_path,
                        traces_dir=self.traces_dir,
                    )

        mock_coordinator_cls.assert_called_once()
        mock_instance.run_trial.assert_called_once()


class TestR11StrictlyQwenOnlyEnforcement(unittest.TestCase):
    """Verify that Mistral Nemo 12B cross-model subset is rejected through every exposed entry point."""

    def test_run_confirmation_suite_rejects_include_mistral(self):
        """Req 1 & 3: Execution function strictly rejects include_mistral=True with ValueError."""
        with self.assertRaises(ValueError) as ctx:
            run_confirmation_suite(execution_authorized=True, include_mistral=True)
        self.assertIn("strictly Qwen-only", str(ctx.exception))
        self.assertIn("Mistral Nemo 12B cross-model subset is permanently disallowed", str(ctx.exception))

    def test_cli_parser_rejects_include_mistral(self):
        """Req 1 & 3: CLI parser exits with error when --include-mistral is passed."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r11.py", "--include-mistral"]):
            with self.assertRaises(SystemExit):
                main()

    def test_validate_runner_reports_strictly_qwen_only_matrix(self):
        """Req 1 & 3: validate_runner reports exactly 36 Qwen runs and 0 Mistral runs."""
        report = validate_runner(verbose=False)
        self.assertEqual(report["status"], "PASS")
        matrix_check = report["checks"]["matrix_dimensions"]
        self.assertEqual(matrix_check["qwen_runs"], 36)
        self.assertEqual(matrix_check["mistral_runs"], 0)
        self.assertEqual(matrix_check["total_planned_runs"], 36)
        self.assertTrue(matrix_check["strictly_qwen_only"])


class TestR11ResourceMonitorFailClosedBehavior(unittest.TestCase):
    """Verify fail-closed behavior when resource-monitoring mechanisms fail or are unavailable."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.summary_path = os.path.join(self.tmp_dir, "phase_03f_confirmation_summary.json")
        self.traces_dir = os.path.join(self.tmp_dir, "traces")
        os.makedirs(self.traces_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("scripts.run_phase_03f_confirmation_r11.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_resource_monitor_failure_at_stage1_fails_closed(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 4: If querying host RAM fails at Stage 1, runner fails closed and dispatches ZERO trials."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        mock_vm.side_effect = OSError("WMI or host memory query failed")
        mock_instance = MagicMock()
        mock_coordinator_cls.return_value = mock_instance

        run_confirmation_suite(
            execution_authorized=True,
            include_mistral=False,
            summary_path=self.summary_path,
            traces_dir=self.traces_dir,
        )

        # Coordinator must NOT be initialized and trial must NOT be run
        mock_coordinator_cls.assert_not_called()
        mock_instance.run_trial.assert_not_called()

        # Summary records fail-closed refusal
        self.assertTrue(os.path.exists(self.summary_path))
        with open(self.summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["stopping_reason"], "RESOURCE_MONITOR_UNAVAILABLE")
        self.assertIn("unable to query initial host RAM", data[0]["error"])

    @patch("scripts.run_phase_03f_confirmation_r11.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_resource_monitor_failure_at_stage2_fails_closed(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 4: If querying host RAM fails at Stage 2, runner fails closed and dispatches ZERO trials."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        vm_7_5 = MagicMock()
        vm_7_5.available = int(7.5 * (1024 ** 3))

        def side_effect():
            if mock_vm.call_count == 1:
                return vm_7_5
            raise RuntimeError("Telemetry pipe broke before dispatch")

        mock_vm.side_effect = side_effect
        mock_instance = MagicMock()
        mock_coordinator_cls.return_value = mock_instance

        run_confirmation_suite(
            execution_authorized=True,
            include_mistral=False,
            summary_path=self.summary_path,
            traces_dir=self.traces_dir,
        )

        # Coordinator was initialized after Stage 1, but run_trial() NEVER called!
        mock_coordinator_cls.assert_called_once()
        mock_instance.run_trial.assert_not_called()

        # Summary records fail-closed refusal
        self.assertTrue(os.path.exists(self.summary_path))
        with open(self.summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["stopping_reason"], "RESOURCE_MONITOR_UNAVAILABLE")
        self.assertIn("unable to query pre-dispatch host RAM", data[0]["error"])

    @patch("scripts.run_phase_03f_confirmation_r11.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_continuous_monitor_start_failure_fails_closed(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 4: If ContinuousRamMonitor fails to start, runner fails closed and dispatches ZERO trials."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        vm_mock = MagicMock()
        vm_mock.available = int(7.5 * (1024 ** 3))
        mock_vm.return_value = vm_mock

        mock_instance = MagicMock()
        mock_coordinator_cls.return_value = mock_instance

        with patch.object(ContinuousRamMonitor, "start", side_effect=RuntimeError("Thread allocation failed")):
            run_confirmation_suite(
                execution_authorized=True,
                include_mistral=False,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )

        mock_instance.run_trial.assert_not_called()
        with open(self.summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["stopping_reason"], "RESOURCE_MONITOR_UNAVAILABLE")
        self.assertIn("continuous RAM monitor failed to start", data[0]["error"])


class TestR11DualStagePreflightGuards(unittest.TestCase):
    """Verify dual-stage pre-flight checks and refusal guarantees."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.summary_path = os.path.join(self.tmp_dir, "phase_03f_confirmation_summary.json")
        self.traces_dir = os.path.join(self.tmp_dir, "traces")
        os.makedirs(self.traces_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("scripts.run_phase_03f_confirmation_r11.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    @patch("src.pipeline.ollama_client.OllamaClient")
    def test_stage1_preflight_refusal_at_6_999_gib_prevents_coordinator_init(
        self, mock_ollama_client, mock_coordinator, mock_vm, mock_val_paths
    ):
        """Req 2: Stage 1 refusal at 6.999 GiB blocks coordinator init, Ollama, and trial dispatch."""
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
            execution_authorized=True,
            include_mistral=False,
            summary_path=self.summary_path,
            traces_dir=self.traces_dir,
        )

        mock_coordinator.assert_not_called()
        mock_ollama_client.assert_not_called()

        self.assertTrue(os.path.exists(self.summary_path))
        with open(self.summary_path, "r", encoding="utf-8") as f:
            summary_data = json.load(f)

        self.assertEqual(len(summary_data), 1)
        record = summary_data[0]
        self.assertEqual(record["stopping_reason"], "RAM_INSUFFICIENT_PRE_FLIGHT_INITIAL")
        self.assertLess(record["ram_available_gb_initial"], 7.0)
        self.assertIn("initial pre-flight check", record["error"])

    @patch("scripts.run_phase_03f_confirmation_r11.validate_output_paths")
    @patch("psutil.virtual_memory")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_stage2_preflight_refusal_at_final_dispatch_check_prevents_trial_run(
        self, mock_coordinator_cls, mock_vm, mock_val_paths
    ):
        """Req 2: RAM at 7.5 GiB during initial pre-flight and 6.8 GiB at final dispatch check -> ZERO trial dispatches."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

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
            execution_authorized=True,
            include_mistral=False,
            summary_path=self.summary_path,
            traces_dir=self.traces_dir,
        )

        mock_coordinator_cls.assert_called_once()
        mock_instance.run_trial.assert_not_called()

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

    @patch("scripts.run_phase_03f_confirmation_r11.validate_output_paths")
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

        with patch.object(ContinuousRamMonitor, "start"), \
             patch.object(ContinuousRamMonitor, "stop", return_value=7.1):
            with patch("scripts.run_phase_03f_confirmation_r11.CONFIRMATION_CONFIGS", [CONFIRMATION_CONFIGS[0]]):
                with patch("scripts.run_phase_03f_confirmation_r11.CONDITIONS", [CONDITIONS[0]]):
                    run_confirmation_suite(
                        execution_authorized=True,
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

    @patch("scripts.run_phase_03f_confirmation_r11.validate_output_paths")
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
            with patch("scripts.run_phase_03f_confirmation_r11.CONFIRMATION_CONFIGS", CONFIRMATION_CONFIGS[:2]):
                with patch("scripts.run_phase_03f_confirmation_r11.CONDITIONS", [CONDITIONS[0]]):
                    run_confirmation_suite(
                        execution_authorized=True,
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


class TestR11SafetyStatusDocumentation(unittest.TestCase):
    """Verify that R11 is explicitly classified as NOT SAFE TO EXECUTE."""

    def test_execution_safety_status_constant(self):
        """Req 2 & 6: Verify EXECUTION_SAFETY_STATUS is strictly NOT SAFE TO EXECUTE."""
        self.assertEqual(EXECUTION_SAFETY_STATUS, "NOT SAFE TO EXECUTE")
        self.assertIn("NOT SAFE TO EXECUTE", SAFETY_LIMITATION_DOCUMENTATION)
        self.assertIn("hard guarantee", SAFETY_LIMITATION_DOCUMENTATION)
        self.assertIn("Windows user-space architecture", SAFETY_LIMITATION_DOCUMENTATION)

    def test_validate_runner_reports_safety_classification(self):
        """Req 2: validate_runner explicitly reports NOT SAFE TO EXECUTE with technical limitation."""
        report = validate_runner(verbose=False)
        self.assertEqual(report["status"], "PASS")  # Static checks pass
        safety_check = report["checks"]["execution_safety_classification"]
        self.assertEqual(safety_check["candidate_classification"], "NOT SAFE TO EXECUTE")
        self.assertFalse(safety_check["is_safe_to_execute"])
        self.assertEqual(safety_check["status"], "NOT_ENFORCEABLE_IN_USERSPACE")


class TestR11PreservedSafeguards(unittest.TestCase):
    """Verify output-path isolation, attribution integrity, and non-executing default mode."""

    def test_output_path_traversal_rejection(self):
        """Req 5: Output path validation rejects traversal outside allowed destinations."""
        bad_summary = os.path.join(PROJECT_ROOT, "reports", "..", "secrets.json")
        res = validate_output_paths(bad_summary, ALLOWED_TRACES_DIR)
        self.assertFalse(res.is_valid)

    def test_attribution_identity_conflict_quarantined(self):
        """Req 5: Gate identity conflicts are quarantined and do not leak into Pass 2 signature matches."""
        class _MockProposal:
            def __init__(self, tool_name, arguments, proposal_id=None):
                self.tool_name, self.arguments, self.proposal_id = tool_name, arguments, proposal_id

        class _MockGate:
            def __init__(self, tool, args, decision_id=None, proposal_id=None, authorized=True):
                self.evaluated_tool, self.evaluated_arguments = tool, args
                self.decision_id, self.proposal_id = decision_id, proposal_id
                self.decision = "ALLOW" if authorized else "DENY"
                self.gate_authorized, self.reason = authorized, "identity collision test"

        p0 = _MockProposal("send_money", {"to": "alice", "amount": 5}, "prop-A")
        fake_link = _MockGate("send_money", {"to": "alice", "amount": 5}, decision_id="prop-A", proposal_id="unrelated-proposal")
        gate_attrs, unclaimed_gates = match_proposals_to_gate_decisions_collection([p0], [fake_link])
        self.assertFalse(gate_attrs[0]["matched"])
        self.assertTrue(unclaimed_gates[0]["identity_conflict"])


if __name__ == "__main__":
    unittest.main()
