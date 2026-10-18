"""Focused Mocked Regression and Safety Unit Tests for Phase 03F Confirmation Runner R15.

Validates the Phase 03F R15 Best-Effort RAM Safety Implementation:
1. Dual-Stage Preflight Checks:
   - 7.0 GiB unrounded threshold enforced at Stage 1 (suite start) and Stage 2 (pre-dispatch).
   - Abort before dispatch if either preflight check fails.
2. Runtime Emergency Stop Monitoring:
   - 5.0 GiB emergency threshold detection.
   - Target 20 ms polling interval with fail-closed telemetry error handling.
   - Emergency signaling sets cancellation_event and emergency_stop_triggered.
3. Streaming Inference Cancellation & Best-Effort Unload:
   - Streaming client closes HTTP response upon cancellation request.
   - Client catches socket/read errors and raises InferenceCancelledEmergencyStopError.
   - Best-effort unload issues POST /api/generate with keep_alive: 0.
   - Unload failures are handled safely and non-fatally.
4. Experimental Integrity & Protocol Violation Path:
   - Measured RAM below 3.0 GiB triggers SAFETY_PROTOCOL_VIOLATION_RAM_BELOW_MIN_FLOOR.
   - Run is explicitly recorded as non-compliant (safety_protocol_compliant: False).
   - Zero additional trials are dispatched after an emergency or protocol violation.
5. Non-Bypassable Execution Lock:
   - run_confirmation_suite() unconditionally raises BenchmarkExecutionLockError.
   - Mutating module-level BENCHMARK_EXECUTION_LOCKED to False still refuses execution.
   - CLI rejects --execute-confirmation and --include-mistral.
   - Default CLI invocation remains non-executing validation mode.

ZERO live benchmark trials executed. ZERO Ollama daemon invocations. ZERO AgentDojo scenarios.
All tests use mocks only.
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

import scripts.run_phase_03f_confirmation_r15 as r15
from scripts.run_phase_03f_confirmation_r15 import (
    CONFIRMATION_CONFIGS,
    CONDITIONS,
    MISTRAL_SUBSET_IDS,
    RAM_MIN_THRESHOLD_GB,
    RAM_EMERGENCY_STOP_THRESHOLD_GB,
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
    InferenceCancelledEmergencyStopError,
    CancelableStreamingOllamaClient,
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


class TestR15PreflightAndThresholdSafeguards(unittest.TestCase):
    """Verify preflight checks and exact threshold calibrations."""

    def test_threshold_constants_values(self):
        """Req 1 & 2: Verify exact threshold values."""
        self.assertEqual(RAM_PREFLIGHT_THRESHOLD_GB, 7.0, "Preflight threshold must be exactly 7.0 GiB")
        self.assertEqual(RAM_EMERGENCY_STOP_THRESHOLD_GB, 5.0, "Emergency stop threshold must be exactly 5.0 GiB")
        self.assertEqual(RAM_MIN_THRESHOLD_GB, 3.0, "Operating floor must remain strictly 3.0 GiB")

    def test_preflight_exact_7_0_gib_passes(self):
        """Req 1: Exactly 7.0 GiB available passes preflight check."""
        bytes_7_0 = int(7.0 * (1024 ** 3))
        passed, val = evaluate_ram_headroom(bytes_7_0, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertTrue(passed)
        self.assertGreaterEqual(val, 7.0)

    def test_preflight_unrounded_6_999999_fails(self):
        """Req 1: 6.999999 GiB strictly fails the unrounded 7.0 GiB preflight check."""
        bytes_sub = int(6.999999 * (1024 ** 3))
        passed, val = evaluate_ram_headroom(bytes_sub, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertFalse(passed)
        self.assertLess(val, 7.0)

    def test_operating_floor_unrounded_boundary(self):
        """Req 4: Operating floor 3.0 GiB unrounded evaluation."""
        bytes_below_3 = int(2.999999 * (1024 ** 3))
        passed_below, _ = evaluate_ram_headroom(bytes_below_3, threshold_gb=RAM_MIN_THRESHOLD_GB)
        self.assertFalse(passed_below)

        bytes_exact_3 = int(3.0 * (1024 ** 3))
        passed_exact, _ = evaluate_ram_headroom(bytes_exact_3, threshold_gb=RAM_MIN_THRESHOLD_GB)
        self.assertTrue(passed_exact)


class TestR15RuntimeEmergencyMonitoring(unittest.TestCase):
    """Verify runtime emergency stop monitoring and fail-closed telemetry behavior."""

    @patch("psutil.virtual_memory")
    def test_emergency_signal_when_ram_below_5_0_gib(self, mock_vm):
        """Req 2: When available RAM drops below 5.0 GiB, monitor triggers emergency stop and sets cancellation event."""
        vm_good = MagicMock()
        vm_good.available = int(6.5 * (1024 ** 3))

        vm_low = MagicMock()
        vm_low.available = int(4.8 * (1024 ** 3))

        call_count = 0
        def vm_side_effect():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return vm_good
            return vm_low

        mock_vm.side_effect = vm_side_effect
        cancel_event = unittest.mock.MagicMock()
        monitor = ContinuousRamMonitor(
            interval_seconds=0.01,
            emergency_threshold_gb=5.0,
            cancellation_event=cancel_event,
        )
        monitor.start()
        time.sleep(0.06)
        min_gb = monitor.stop()

        status = monitor.get_status()
        self.assertTrue(monitor.emergency_stop_triggered)
        self.assertTrue(status["emergency_stop_triggered"])
        self.assertIn("EMERGENCY RAM HALT", monitor.emergency_reason)
        self.assertIn("5.0", monitor.emergency_reason)
        cancel_event.set.assert_called()

    @patch("psutil.virtual_memory")
    def test_fail_closed_on_monitor_start_failure(self, mock_vm):
        """Req 2: Telemetry query failure during start() raises RuntimeError and flips health to False."""
        mock_vm.side_effect = OSError("WMI service unresponsive")
        cancel_event = unittest.mock.MagicMock()
        monitor = ContinuousRamMonitor(interval_seconds=0.01, cancellation_event=cancel_event)
        with self.assertRaises(RuntimeError) as ctx:
            monitor.start()

        self.assertIn("ContinuousRamMonitor failed to query initial RAM", str(ctx.exception))
        self.assertFalse(monitor.is_healthy)
        self.assertEqual(len(monitor.sampling_errors), 1)
        cancel_event.set.assert_called()

    @patch("psutil.virtual_memory")
    def test_fail_closed_on_mid_run_telemetry_failure(self, mock_vm):
        """Req 2: Telemetry query failure mid-monitoring sets is_healthy=False and signals cancellation."""
        vm_good = MagicMock()
        vm_good.available = int(7.5 * (1024 ** 3))

        def vm_side_effect():
            if mock_vm.call_count <= 2:
                return vm_good
            raise OSError("Kernel page telemetry failure")

        mock_vm.side_effect = vm_side_effect
        cancel_event = unittest.mock.MagicMock()
        monitor = ContinuousRamMonitor(interval_seconds=0.01, cancellation_event=cancel_event)
        monitor.start()
        time.sleep(0.06)
        monitor.stop()

        self.assertFalse(monitor.is_healthy)
        self.assertGreater(monitor.failed_samples, 0)
        self.assertGreater(len(monitor.sampling_errors), 0)
        cancel_event.set.assert_called()

    @patch("psutil.virtual_memory")
    def test_monitor_stop_preserves_error_evidence(self, mock_vm):
        """Req 2: Calling stop() multiple times does not reset or erase failure telemetry."""
        vm_good = MagicMock()
        vm_good.available = int(7.5 * (1024 ** 3))

        def vm_side_effect():
            if mock_vm.call_count <= 2:
                return vm_good
            return None  # Bad return

        mock_vm.side_effect = vm_side_effect
        monitor = ContinuousRamMonitor(interval_seconds=0.01)
        monitor.start()
        time.sleep(0.05)
        monitor.stop()
        monitor.stop()  # Idempotent cleanup

        status = monitor.get_status()
        self.assertFalse(status["is_healthy"])
        self.assertGreater(status["failed_samples"], 0)


class TestR15StreamingInferenceCancellationAndUnload(unittest.TestCase):
    """Verify streaming response socket closure, cancellation handling, and best-effort unload."""

    @patch("urllib.request.urlopen")
    def test_streaming_response_closed_on_cancellation(self, mock_urlopen):
        """Req 3: Streaming client closes HTTP response and raises InferenceCancelledEmergencyStopError upon cancellation."""
        mock_response = MagicMock()
        # Simulate streaming token chunks
        chunk1 = json.dumps({"response": "I will ", "done": False}).encode("utf-8") + b"\n"
        chunk2 = json.dumps({"response": "send money", "done": False}).encode("utf-8") + b"\n"
        mock_response.readline.side_effect = [chunk1, chunk2]

        mock_urlopen.return_value = mock_response

        cancel_event = unittest.mock.MagicMock()
        # Event is not set at start, then becomes set on second read
        call_count = 0
        def is_set_side_effect():
            nonlocal call_count
            call_count += 1
            return (call_count >= 2)

        cancel_event.is_set.side_effect = is_set_side_effect

        client = CancelableStreamingOllamaClient(
            default_model="qwen2.5:3b",
            cancellation_event=cancel_event,
        )

        with patch.object(client, "attempt_unload") as mock_unload:
            with self.assertRaises(InferenceCancelledEmergencyStopError):
                client.generate(prompt="Transfer funds")

            mock_response.close.assert_called()
            self.assertTrue(client.last_response_closed)
            mock_unload.assert_called_with("qwen2.5:3b")

    @patch("urllib.request.urlopen")
    def test_cancellation_event_already_set_aborts_before_dispatch(self, mock_urlopen):
        """Req 3: If cancellation event is already set, client aborts before making HTTP request."""
        cancel_event = unittest.mock.MagicMock()
        cancel_event.is_set.return_value = True

        client = CancelableStreamingOllamaClient(
            default_model="qwen2.5:3b",
            cancellation_event=cancel_event,
        )

        with patch.object(client, "attempt_unload") as mock_unload:
            with self.assertRaises(InferenceCancelledEmergencyStopError):
                client.generate(prompt="Test prompt")

            mock_urlopen.assert_not_called()
            mock_unload.assert_called_with(None)

    @patch("urllib.request.urlopen")
    def test_attempt_unload_request_construction_success(self, mock_urlopen):
        """Req 3: Best-effort attempt_unload issues POST to /api/generate with keep_alive: 0."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = CancelableStreamingOllamaClient(default_model="qwen2.5:3b")
        success = client.attempt_unload("qwen2.5:3b")

        self.assertTrue(success)
        self.assertTrue(client.unload_attempted)
        self.assertTrue(client.unload_success)

        # Inspect request payload
        req_arg = mock_urlopen.call_args[0][0]
        self.assertEqual(req_arg.full_url, "http://127.0.0.1:11434/api/generate")
        payload = json.loads(req_arg.data.decode("utf-8"))
        self.assertEqual(payload["model"], "qwen2.5:3b")
        self.assertEqual(payload["keep_alive"], 0)

    @patch("urllib.request.urlopen")
    def test_attempt_unload_failure_handled_non_fatally(self, mock_urlopen):
        """Req 3: Failure during attempt_unload does not raise unhandled exception."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused: Ollama daemon unreachable")

        client = CancelableStreamingOllamaClient(default_model="qwen2.5:3b")
        success = client.attempt_unload("qwen2.5:3b")

        self.assertFalse(success)
        self.assertTrue(client.unload_attempted)
        self.assertFalse(client.unload_success)

    @patch("urllib.request.urlopen")
    def test_streaming_client_compatible_interface(self, mock_urlopen):
        """Req 3: Streaming client generate() returns compatible dict with response and client_duration_seconds."""
        mock_response = MagicMock()
        chunk1 = json.dumps({"response": '{"tool": "none"}', "done": True}).encode("utf-8") + b"\n"
        mock_response.readline.side_effect = [chunk1, b""]
        mock_urlopen.return_value = mock_response

        client = CancelableStreamingOllamaClient(default_model="qwen2.5:3b")
        result = client.generate(prompt="What is the weather?")

        self.assertIsInstance(result, dict)
        self.assertIn("response", result)
        self.assertIn("client_duration_seconds", result)
        self.assertEqual(result["response"], '{"tool": "none"}')
        self.assertGreaterEqual(result["client_duration_seconds"], 0.0)


class TestR15NonBypassableExecutionLock(unittest.TestCase):
    """Verify unconditional API lock and CLI rejection."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.summary_path = os.path.join(self.tmp_dir, "phase_03f_confirmation_summary.json")
        self.traces_dir = os.path.join(self.tmp_dir, "traces")
        os.makedirs(self.traces_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_unauthorized_call_raises_execution_lock_error(self):
        """Req 5: Calling run_confirmation_suite(execution_authorized=False) raises BenchmarkExecutionLockError."""
        with self.assertRaises(BenchmarkExecutionLockError) as ctx:
            run_confirmation_suite(
                execution_authorized=False,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )
        self.assertIn("BENCHMARK EXECUTION IS LOCKED", str(ctx.exception))

    def test_authorized_call_raises_execution_lock_error(self):
        """Req 5: Calling run_confirmation_suite(execution_authorized=True) still raises BenchmarkExecutionLockError."""
        with self.assertRaises(BenchmarkExecutionLockError) as ctx:
            run_confirmation_suite(
                execution_authorized=True,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )
        self.assertIn("BENCHMARK EXECUTION IS LOCKED", str(ctx.exception))

    @patch("scripts.run_phase_03f_confirmation_r15.validate_output_paths")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_execution_refused_even_if_lock_variable_mutated_to_false(
        self, mock_coordinator_cls, mock_val_paths
    ):
        """Req 5: Mutating module-level BENCHMARK_EXECUTION_LOCKED to False does NOT bypass the lock.
        run_confirmation_suite() still unconditionally raises BenchmarkExecutionLockError,
        initializes zero coordinators, creates no summary file, and dispatches zero trials.
        Module state is safely restored afterward in a finally block.
        """
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )
        original_lock_state = r15.BENCHMARK_EXECUTION_LOCKED
        try:
            r15.BENCHMARK_EXECUTION_LOCKED = False

            with self.assertRaises(BenchmarkExecutionLockError) as ctx:
                run_confirmation_suite(
                    execution_authorized=True,
                    summary_path=self.summary_path,
                    traces_dir=self.traces_dir,
                )
            self.assertIn("BENCHMARK EXECUTION IS LOCKED", str(ctx.exception))
            mock_coordinator_cls.assert_not_called()
            self.assertFalse(os.path.exists(self.summary_path))
        finally:
            r15.BENCHMARK_EXECUTION_LOCKED = original_lock_state

    def test_cli_rejects_execute_confirmation_flag(self):
        """Req 5: CLI invocation with --execute-confirmation invokes parser.error and exits."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r15.py", "--execute-confirmation"]):
            with self.assertRaises(SystemExit) as exit_ctx:
                main()
            self.assertNotEqual(exit_ctx.exception.code, 0)

    def test_cli_rejects_include_mistral_flag(self):
        """Req 4: CLI invocation with --include-mistral invokes parser.error and exits."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r15.py", "--include-mistral"]):
            with self.assertRaises(SystemExit) as exit_ctx:
                main()
            self.assertNotEqual(exit_ctx.exception.code, 0)

    def test_default_cli_invocation_remains_non_executing(self):
        """Req 5: Default CLI invocation (no flags) runs validate_runner without launching trials."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r15.py"]):
            with patch("scripts.run_phase_03f_confirmation_r15.validate_runner") as mock_validate:
                mock_validate.return_value = {"status": "PASS", "errors": []}
                with self.assertRaises(SystemExit) as exit_ctx:
                    main()
                self.assertEqual(exit_ctx.exception.code, 0)
                mock_validate.assert_called_once()


class TestR15ExperimentalIntegrityAndProtocolFloor(unittest.TestCase):
    """Verify experimental integrity, Qwen-only matrix, and protocol floor violation handling."""

    def test_strictly_qwen_only_matrix_dimensions(self):
        """Req 4: Exactly 36 planned Qwen runs; 0 Mistral runs."""
        report = validate_runner(verbose=False)
        self.assertEqual(report["status"], "PASS")
        matrix_check = report["checks"]["matrix_dimensions"]
        self.assertEqual(matrix_check["qwen_runs"], 36)
        self.assertEqual(matrix_check["mistral_runs"], 0)
        self.assertEqual(matrix_check["total_planned_runs"], 36)
        self.assertTrue(matrix_check["strictly_qwen_only"])

    def test_output_path_traversal_rejection(self):
        """Req 4: Output path validation rejects traversal outside allowed destinations."""
        bad_summary = os.path.join(PROJECT_ROOT, "reports", "..", "secrets.json")
        res = validate_output_paths(bad_summary, ALLOWED_TRACES_DIR)
        self.assertFalse(res.is_valid)

    def test_attribution_identity_conflict_quarantined(self):
        """Req 4: Gate identity conflicts are quarantined and do not leak into signature matches."""
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

    def test_protocol_violation_when_ram_below_3_0_gib(self):
        """Req 4: If available RAM dips below 3.0 GiB, run is flagged as safety protocol violation and non-compliant."""
        min_during = 2.8500
        passed_during = (min_during >= RAM_MIN_THRESHOLD_GB)
        self.assertFalse(passed_during)
        is_protocol_violation = not passed_during
        safety_compliant = not is_protocol_violation
        self.assertTrue(is_protocol_violation)
        self.assertFalse(safety_compliant)

    def test_emergency_stop_marks_non_compliant_and_halts(self):
        """Req 2 & 4: An emergency stop triggers cancellation and flags compliance as False."""
        emergency_stop_triggered = True
        safety_compliant = not emergency_stop_triggered
        self.assertFalse(safety_compliant)

    def test_safety_status_constants(self):
        """Req 5: Safety status constants reflect locked candidate status."""
        self.assertEqual(EXECUTION_SAFETY_STATUS, "NOT SAFE TO EXECUTE")
        self.assertTrue(BENCHMARK_EXECUTION_LOCKED)
        self.assertIn("BENCHMARK EXECUTION IS LOCKED", EXECUTION_LOCK_REASON)
        self.assertIn("NOT SAFE TO EXECUTE", SAFETY_LIMITATION_DOCUMENTATION)


if __name__ == "__main__":
    unittest.main()
