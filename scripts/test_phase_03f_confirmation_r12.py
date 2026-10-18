"""Comprehensive Regression and Safety Unit Tests for Phase 03F Confirmation Runner R12.

Validates the Phase 03F R12 Candidate:
1. Non-Bypassable Execution Lock:
   - run_confirmation_suite(execution_authorized=False) raises BenchmarkExecutionLockError.
   - run_confirmation_suite(execution_authorized=True) raises BenchmarkExecutionLockError.
   - CLI invocation with --execute-confirmation raises parser error and exits.
   - Zero coordinator initializations and zero trial dispatches for every execution attempt.
   - Default CLI invocation remains non-executing validation mode.
2. Explicit, Inspectable Monitor Failure Tracking:
   - Initial query failure in ContinuousRamMonitor.start() raises RuntimeError and populates sampling_errors.
   - Mid-monitoring sampling failure sets is_healthy = False, increments failed_samples, and records error in sampling_errors.
   - Stale RAM measurements are NOT treated as healthy proof.
   - stop() cleanly shuts down worker thread without erasing or resetting the captured failure state.
   - get_status() exposes complete inspectable diagnostic state.
3. Strictly Qwen-Only enforcement across all exposed boundaries:
   - CLI invocation with --include-mistral triggers parser error and exits.
   - Matrix dimension check verifies 36 Qwen runs and 0 Mistral runs (strictly_qwen_only: True).
4. Safety Status & Validation Reporting:
   - EXECUTION_SAFETY_STATUS is strictly "NOT SAFE TO EXECUTE".
   - BENCHMARK_EXECUTION_LOCKED is strictly True.
   - validate_runner() explicitly reports structural integrity PASS while reporting execution safety NOT SAFE TO EXECUTE (LOCKED).
5. Preserved Core Safeguards:
   - Output path containment and traversal rejection.
   - Attribution identity collision quarantine.
   - Threshold calibration: RAM_PREFLIGHT_THRESHOLD_GB = 7.0 and RAM_MIN_THRESHOLD_GB = 3.0.

Zero benchmark trials executed. Zero LLM inferences.
"""

import os
import sys
import json
import time
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.run_phase_03f_confirmation_r12 import (
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
    BENCHMARK_EXECUTION_LOCKED,
    EXECUTION_LOCK_REASON,
    SAFETY_LIMITATION_DOCUMENTATION,
    BenchmarkExecutionLockError,
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


class TestR12NonBypassableExecutionLock(unittest.TestCase):
    """Verify that benchmark execution is strictly and non-bypassably locked."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.summary_path = os.path.join(self.tmp_dir, "phase_03f_confirmation_summary.json")
        self.traces_dir = os.path.join(self.tmp_dir, "traces")
        os.makedirs(self.traces_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_unauthorized_call_raises_execution_lock_error(self):
        """Req 2: Calling run_confirmation_suite(execution_authorized=False) raises BenchmarkExecutionLockError."""
        with self.assertRaises(BenchmarkExecutionLockError) as ctx:
            run_confirmation_suite(
                execution_authorized=False,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )
        self.assertIn("BENCHMARK EXECUTION IS LOCKED", str(ctx.exception))

    def test_authorized_call_raises_execution_lock_error(self):
        """Req 2: Calling run_confirmation_suite(execution_authorized=True) still raises BenchmarkExecutionLockError."""
        with self.assertRaises(BenchmarkExecutionLockError) as ctx:
            run_confirmation_suite(
                execution_authorized=True,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )
        self.assertIn("BENCHMARK EXECUTION IS LOCKED", str(ctx.exception))

    def test_cli_rejects_execute_confirmation_flag(self):
        """Req 2: CLI invocation with --execute-confirmation invokes parser.error and exits."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r12.py", "--execute-confirmation"]):
            with self.assertRaises(SystemExit) as exit_ctx:
                main()
            self.assertNotEqual(exit_ctx.exception.code, 0)

    @patch("scripts.run_phase_03f_confirmation_r12.validate_output_paths")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_zero_coordinators_and_zero_trials_on_execution_attempts(
        self, mock_coordinator_cls, mock_val_paths
    ):
        """Req 2: Every execution attempt guarantees ZERO coordinator initializations and ZERO trial dispatches."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )

        # Attempt 1: unauthorized
        with self.assertRaises(BenchmarkExecutionLockError):
            run_confirmation_suite(
                execution_authorized=False,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )
        mock_coordinator_cls.assert_not_called()
        self.assertFalse(os.path.exists(self.summary_path))

        # Attempt 2: authorized
        with self.assertRaises(BenchmarkExecutionLockError):
            run_confirmation_suite(
                execution_authorized=True,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )
        mock_coordinator_cls.assert_not_called()
        self.assertFalse(os.path.exists(self.summary_path))

    def test_default_cli_invocation_remains_non_executing(self):
        """Req 2 & 5: Default CLI invocation (no flags) runs validate_runner without launching trials."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r12.py"]):
            with patch("scripts.run_phase_03f_confirmation_r12.validate_runner") as mock_validate:
                mock_validate.return_value = {"status": "PASS", "errors": []}
                with self.assertRaises(SystemExit) as exit_ctx:
                    main()
                self.assertEqual(exit_ctx.exception.code, 0)
                mock_validate.assert_called_once()

    def test_default_cli_invocation_end_to_end_validation(self):
        """Req 2 & 5: Default CLI invocation completes end-to-end static validation with status PASS."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r12.py"]):
            with self.assertRaises(SystemExit) as exit_ctx:
                main()
            self.assertEqual(exit_ctx.exception.code, 0)


class TestR12ContinuousRamMonitorDiagnostics(unittest.TestCase):
    """Verify that ContinuousRamMonitor tracks failures explicitly without swallowing errors."""

    @patch("psutil.virtual_memory")
    def test_monitor_initial_start_failure_captured_and_raised(self, mock_vm):
        """Req 3: Failure at start() raises RuntimeError and populates sampling_errors."""
        mock_vm.side_effect = OSError("WMI connection refused")
        monitor = ContinuousRamMonitor(interval_seconds=0.01)
        with self.assertRaises(RuntimeError) as ctx:
            monitor.start()
        self.assertIn("ContinuousRamMonitor failed to query initial RAM", str(ctx.exception))
        self.assertFalse(monitor.is_healthy)
        self.assertEqual(len(monitor.sampling_errors), 1)

    @patch("psutil.virtual_memory")
    def test_monitor_mid_sampling_failure_recorded_and_exposed(self, mock_vm):
        """Req 3: Sampling failure mid-run sets is_healthy=False and records explicit error in state."""
        vm_good = MagicMock()
        vm_good.available = int(7.5 * (1024 ** 3))

        # First sample in start() succeeds; subsequent samples in thread fail
        def vm_side_effect():
            if mock_vm.call_count <= 2:
                return vm_good
            raise OSError("Kernel memory query timeout")

        mock_vm.side_effect = vm_side_effect
        monitor = ContinuousRamMonitor(interval_seconds=0.02)
        monitor.start()
        time.sleep(0.10)
        min_gb = monitor.stop()

        status = monitor.get_status()
        self.assertFalse(monitor.is_healthy, "Monitor must report is_healthy=False when a sample fails")
        self.assertFalse(status["is_healthy"])
        self.assertGreater(monitor.failed_samples, 0, "failed_samples counter must be incremented")
        self.assertGreater(len(monitor.sampling_errors), 0, "sampling_errors must capture failure text")
        self.assertIn("Kernel memory query timeout", monitor.sampling_errors[0])
        self.assertGreater(min_gb, 0.0, "Valid prior measurement must still be returned")

    @patch("psutil.virtual_memory")
    def test_stale_ram_measurements_not_treated_as_healthy(self, mock_vm):
        """Req 3: Stale RAM measurement is NOT treated as proof of health when failures occurred."""
        vm_good = MagicMock()
        vm_good.available = int(7.5 * (1024 ** 3))

        call_idx = 0
        def vm_side_effect():
            nonlocal call_idx
            call_idx += 1
            if call_idx <= 2:
                return vm_good
            return None  # Telemetry returns invalid object

        mock_vm.side_effect = vm_side_effect
        monitor = ContinuousRamMonitor(interval_seconds=0.02)
        monitor.start()
        time.sleep(0.10)
        min_gb = monitor.stop()

        # Despite min_gb showing 7.5 GiB, health must be FALSE
        self.assertFalse(monitor.is_healthy)
        self.assertGreater(monitor.failed_samples, 0)
        self.assertIn("None or missing", monitor.sampling_errors[0])

    @patch("psutil.virtual_memory")
    def test_stop_cleanup_does_not_erase_monitoring_failures(self, mock_vm):
        """Req 3: Cleanup via stop() does NOT erase or reset the captured diagnostic failure state."""
        vm_good = MagicMock()
        vm_good.available = int(7.5 * (1024 ** 3))

        def vm_side_effect():
            if mock_vm.call_count <= 2:
                return vm_good
            raise RuntimeError("Telemetry pipe broke")

        mock_vm.side_effect = vm_side_effect
        monitor = ContinuousRamMonitor(interval_seconds=0.02)
        monitor.start()
        time.sleep(0.08)

        # Stop multiple times (simulating stop() and finally: stop() cleanup)
        monitor.stop()
        monitor.stop()

        # Verification: errors must STILL be present
        self.assertFalse(monitor.is_healthy)
        self.assertGreater(len(monitor.sampling_errors), 0)
        self.assertIn("Telemetry pipe broke", monitor.sampling_errors[0])


class TestR12StrictlyQwenOnlyEnforcement(unittest.TestCase):
    """Verify that Mistral Nemo 12B cross-model subset is rejected across all exposed boundaries."""

    def test_cli_parser_rejects_include_mistral(self):
        """Req 1 & 3: CLI parser exits with error when --include-mistral is passed."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r12.py", "--include-mistral"]):
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


class TestR12SafetyStatusAndValidationMode(unittest.TestCase):
    """Verify that R12 explicitly reports NOT SAFE TO EXECUTE while structural validation passes."""

    def test_execution_safety_status_constants(self):
        """Req 4: Verify EXECUTION_SAFETY_STATUS and BENCHMARK_EXECUTION_LOCKED constants."""
        self.assertEqual(EXECUTION_SAFETY_STATUS, "NOT SAFE TO EXECUTE")
        self.assertTrue(BENCHMARK_EXECUTION_LOCKED)
        self.assertIn("BENCHMARK EXECUTION IS LOCKED", EXECUTION_LOCK_REASON)
        self.assertIn("NOT SAFE TO EXECUTE", SAFETY_LIMITATION_DOCUMENTATION)
        self.assertIn("permanently LOCKED", SAFETY_LIMITATION_DOCUMENTATION)

    def test_validate_runner_reports_structural_pass_and_execution_locked(self):
        """Req 2, 4 & 5: validate_runner reports status PASS for structural checks but LOCKED for execution safety."""
        report = validate_runner(verbose=False)
        self.assertEqual(report["status"], "PASS", "Structural checks must pass")
        self.assertEqual(len(report["errors"]), 0, "Zero structural errors expected")

        safety_check = report["checks"]["execution_safety_classification"]
        self.assertEqual(safety_check["status"], "LOCKED")
        self.assertEqual(safety_check["candidate_classification"], "NOT SAFE TO EXECUTE")
        self.assertFalse(safety_check["is_safe_to_execute"])
        self.assertTrue(safety_check["benchmark_execution_locked"])

        lock_check = report["checks"]["non_bypassable_execution_lock"]
        self.assertEqual(lock_check, "PASS")


class TestR12PreservedSafeguards(unittest.TestCase):
    """Verify threshold calibration, output-path isolation, and attribution integrity."""

    def test_threshold_constants_values(self):
        """Req 4: Verify exact threshold values."""
        self.assertEqual(RAM_PREFLIGHT_THRESHOLD_GB, 7.0, "Pre-flight threshold must be exactly 7.0 GB")
        self.assertEqual(RAM_MIN_THRESHOLD_GB, 3.0, "Hard monitoring threshold must remain strictly 3.0 GB")

    def test_preflight_unrounded_boundary_6_999_refusal(self):
        """Req 4: 6.999 GiB available must strictly fail pre-flight threshold."""
        bytes_6_999 = int(6.999 * (1024 ** 3))
        passed, val = evaluate_ram_headroom(bytes_6_999, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertFalse(passed, "6.999 GiB must fail the 7.0 GiB pre-flight threshold")
        self.assertLess(val, 7.0)

    def test_hard_3_0_gib_monitoring_threshold_unchanged(self):
        """Req 4: Hard 3.0 GiB monitoring threshold remains unchanged and strictly enforced."""
        bytes_below = int(2.999999 * (1024 ** 3))
        passed_below, val_below = evaluate_ram_headroom(bytes_below, threshold_gb=RAM_MIN_THRESHOLD_GB)
        self.assertFalse(passed_below, "2.999999 GiB must fail the 3.0 GiB monitoring threshold")
        self.assertLess(val_below, 3.0)

        bytes_exact = int(3.00000000 * (1024 ** 3))
        passed_exact, val_exact = evaluate_ram_headroom(bytes_exact, threshold_gb=RAM_MIN_THRESHOLD_GB)
        self.assertTrue(passed_exact, "Exactly 3.0 GiB must pass the 3.0 GiB monitoring threshold")
        self.assertGreaterEqual(val_exact, 3.0)

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
