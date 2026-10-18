# Phase 03F R16.2 — Minimal Single-Trial Research Prototype Implementation Report

**Date**: 2026-10-17  
**Candidate Runner**: [`scripts/run_phase_03f_single_trial_r16_2.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_2.py)  
**Dedicated Test Suite**: [`scripts/test_phase_03f_single_trial_r16_2.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_2.py)  
**Candidate Safety Status**: `PROTOTYPE CANDIDATE — AWAITING STATIC REVIEW (EXECUTION LOCKED BY DEFAULT)`  
**Operational Policy**: Approved Best-Effort Resource Management (7.0 GiB dual-stage preflight checks, 5.0 GiB emergency stop with continuous 20 ms monitoring, post-setup Stage 2 preflight refusal with monitor shutdown, full proposal evidence preservation, fail-closed missing trace handling, null unknown outcomes on insufficient evidence, zero-side-effect API authorization gate, and 3.0 GiB non-compliant protocol violation floor).  

---

## 1. Executive Summary & Verification Verdict

| Verification Item | Implementation & Verification Details | Status |
|---|---|---|
| **Historical Candidate Preservation** | R8 through R16.1 remain completely unmodified. Reference repo `D:\Agent_watch_prov` is strictly read-only. Git state unmodified. | **VERIFIED** |
| **Correction 1: Missing Trace Exposure Classification** | When a trial terminates without producing a `TraceRecord`, exposure is classified as `UNRESOLVED_NO_TRACE` for attacked configurations (and `NOT_APPLICABLE` for benign), never falsely attributed as `UNEXPOSED`. | **VERIFIED** |
| **Correction 2: Null Unknown Outcomes on Insufficient Evidence** | Trace-dependent outcome metrics (`security_breach`, `environment_mutated`, `execution_completed`, `execution_attempted`, `gate_authorized`, `utility_success`) are set to `null` (`None`) when trace evidence is absent, avoiding false security or utility success claims. | **VERIFIED** |
| **Correction 3: Exception Preservation & Fail-Closed Audit** | Preserves root trial exception in `trial_exception` and `stopping_reason`, records status as `FAILED`, and marks the audit incomplete (`INCOMPLETE_AUDIT_TRIAL_EXCEPTION`) and non-compliant (`safety_protocol_compliant = False`). | **VERIFIED** |
| **Correction 4: Clean API Authorization Gate (Zero Side Effects)** | The `execution_authorized` check is evaluated before Stage 1 preflight headroom checks and before any refusal or summary file writes, ensuring unauthorized calls produce zero persistent side effects. | **VERIFIED** |
| **Single-Trial Scope & Qwen-Only** | Exactly one trial per invocation; no matrix loops, retries, or parallel execution. Strictly `qwen2.5:3b`. Mistral Nemo 12B remains permanently disabled. | **VERIFIED** |
| **Dual-Stage Preflight & Best-Effort RAM Safety** | Preserves Stage 1 (pre-setup) and Stage 2 (post-setup, pre-dispatch) 7.0 GiB headroom checks, 5.0 GiB emergency stop, and 3.0 GiB operating floor. Output collision and overwrite protections remain active. No hard RAM guarantee claimed. | **VERIFIED** |
| **Default Validation Mode** | Default CLI invocation runs non-executing validation only. API requires explicit `execution_authorized=True`; CLI requires `--execute-single-trial`. | **VERIFIED** |
| **Dedicated Mocked Unit Tests** | 17/17 dedicated mocked unit tests passing in 0.151s in `.venv`. Zero live Ollama calls, zero AgentDojo executions. | **VERIFIED** |
| **Final Implementation Verdict** | **`READY FOR STATIC REVIEW`** | **VERIFIED** |

---

## 2. Implemented Remediations & Code Locations

### 2.1 Correction 1: Missing Trace Exposure Classification (`UNRESOLVED_NO_TRACE`)
- **Code Location**: [`scripts/run_phase_03f_single_trial_r16_2.py#L859-L869`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_2.py#L859-L869)
- **Problem**: In R16 and R16.1, if a trial aborted before creating a `TraceRecord` (e.g. coordinator exception, emergency stop, or network failure), `evaluate_injection_exposure` fell through to `UNEXPOSED`. This created a critical false-negative report where an aborted attack trial was recorded as evidence that the model resisted injection.
- **Implemented Remediation**:
  ```python
  # Requirement 1: If trial failed without producing a TraceRecord, classify as UNRESOLVED_NO_TRACE
  if trace is None:
      return {
          "exposure_confirmed": False,
          "target_entity_observed": None,
          "injection_text_observed": None,
          "partial_payload_observed": None,
          "exposure_status": "UNRESOLVED_NO_TRACE",
          "evidence": [],
      }
  ```
  - For benign tasks, line 850 immediately returns `exposure_status = "NOT_APPLICABLE"`.
  - For attacked tasks without trace, returns `UNRESOLVED_NO_TRACE` with observed flags set to `None` (`null` in JSON).
- **Test Verification**:
  - [`scripts/test_phase_03f_single_trial_r16_2.py#L60-L75`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_2.py#L60-L75) (`test_evaluate_injection_exposure_without_trace`): Verifies `UNRESOLVED_NO_TRACE` on attacked configs and `NOT_APPLICABLE` on benign configs when `trace=None`.

### 2.2 Correction 2: Null Unknown Outcomes on Insufficient Evidence
- **Code Location**: [`scripts/run_phase_03f_single_trial_r16_2.py#L1178-L1193`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_2.py#L1178-L1193)
- **Problem**: In earlier candidates, default boolean falses (`security_breach = False`, `environment_mutated = False`, `utility_success = False`) were recorded if no trace was generated. Setting `security_breach = False` falsely implied the security policy successfully prevented an attack, when in reality no execution or evaluation occurred.
- **Implemented Remediation**:
  ```python
  if trace is not None:
      gate_authorized = getattr(trace, "gate_authorized", None)
      execution_attempted = getattr(trace, "execution_attempted", None)
      execution_completed = getattr(trace, "execution_completed", None)
      environment_mutated = getattr(trace, "environment_mutated", None)
      utility_success = getattr(trace, "utility_success", None)
      security_breach = getattr(trace, "security_breach", None)
  else:
      gate_authorized = None
      execution_attempted = None
      execution_completed = None
      environment_mutated = None
      utility_success = None
      security_breach = None
  ```
  - In JSON serialization, `None` values render as `null`, accurately representing unassessed outcomes due to insufficient trace evidence.
- **Test Verification**:
  - [`scripts/test_phase_03f_single_trial_r16_2.py#L77-L138`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_2.py#L77-L138) (`test_trial_exception_sets_null_outcomes_and_incomplete_audit`): Simulates trial exception during `coordinator.run_trial()`. Verifies that saved JSON evidence contains `null` for `security_breach`, `environment_mutated`, `utility_success`, `execution_completed`, etc.

### 2.3 Correction 3: Exception Preservation & Fail-Closed Audit
- **Code Location**: [`scripts/run_phase_03f_single_trial_r16_2.py#L751-L756`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_2.py#L751-L756), [`#L795-L796`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_2.py#L795-L796), [`#L1198`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_2.py#L1198), [`#L1230`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_2.py#L1230)
- **Problem**: Trial exceptions could be swallowed or recorded without flagging the trial audit as incomplete and non-compliant.
- **Implemented Remediation**:
  - `evaluate_trial_safety_and_compliance` now explicitly treats `trial_exception is not None` as an incomplete audit condition:
    ```python
    if trial_exception is not None:
        incomplete_audit = True
        if audit_status == "COMPLETE_AUDIT":
            audit_status = "INCOMPLETE_AUDIT_TRIAL_EXCEPTION"
    ```
  - Sets `stopping_reason = f"UNHANDLED_EXCEPTION: {type(trial_exception).__name__}: {str(trial_exception)}"`.
  - Sets `safety_protocol_compliant = False`.
  - Records trial run `status = "FAILED"`.
  - Preserves the root exception string with type: `"trial_exception": f"{type(trial_exception).__name__}: {str(trial_exception)}"`.
- **Test Verification**:
  - [`scripts/test_phase_03f_single_trial_r16_2.py#L77-L138`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_2.py#L77-L138): Confirms `res["status"] == "FAILED"`, `res["trial_exception"]` contains exception type and message, `audit_status == "INCOMPLETE_AUDIT_TRIAL_EXCEPTION"`, and `safety_protocol_compliant == False`.

### 2.4 Correction 4: Clean API Authorization Gate (Zero Side Effects)
- **Code Location**: [`scripts/run_phase_03f_single_trial_r16_2.py#L1045-L1050`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_2.py#L1045-L1050)
- **Problem**: In R16.1, `run_single_trial` checked Stage 1 available RAM before verifying `execution_authorized`. If available RAM was low (< 7.0 GiB), an unauthorized API call (`execution_authorized=False`) wrote a `REFUSED_PREFLIGHT_STAGE1` summary file to disk before failing, violating the invariant that unauthorized calls must have zero persistent side effects.
- **Implemented Remediation**:
  - Moved the `if not execution_authorized:` check to the very beginning of `run_single_trial`, ahead of any Stage 1 headroom queries or refusal file writes:
    ```python
    # Requirement 4: Explicit Execution Authorization Gate AHEAD OF ANY PREFLIGHT FILE WRITES
    # Ensures unauthorized calls produce zero persistent side effects (no summary/refusal files written).
    if not execution_authorized:
        raise SingleTrialExecutionNotAuthorizedError(
            "Explicit execution authorization required: execution_authorized must be set to True to dispatch a single trial."
        )
    ```
- **Test Verification**:
  - [`scripts/test_phase_03f_single_trial_r16_2.py#L141-L177`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_2.py#L141-L177) (`test_unauthorized_call_with_low_ram_writes_zero_files`): Simulates available RAM at 2.0 GiB (which would fail Stage 1). Confirms `SingleTrialExecutionNotAuthorizedError` is raised, coordinator setup is never touched, and zero files are written to disk.

---

## 3. Dedicated Mocked Test Results (`scripts/test_phase_03f_single_trial_r16_2.py`)

**Execution Command**:
```powershell
.\.venv\Scripts\python.exe -m unittest scripts/test_phase_03f_single_trial_r16_2.py -v
```

**Complete Test Execution Log**:
```text
test_api_rejects_unauthorized_call (scripts.test_phase_03f_single_trial_r16_2.TestR162AuthorizationGate.test_api_rejects_unauthorized_call)
API call with execution_authorized=False raises exception. ... ok
test_default_cli_invocation_is_validation_only (scripts.test_phase_03f_single_trial_r16_2.TestR162AuthorizationGate.test_default_cli_invocation_is_validation_only)
CLI without --execute-single-trial defaults to validation only. ... 
[SAFETY NOTICE] Runner invoked without --execute-single-trial.
Defaulting to non-executing validation mode. Zero model calls, zero AgentDojo executions.

================================================================================
PHASE 03F R16.2: SINGLE-TRIAL RUNNER VALIDATION REPORT
================================================================================
Validation Status:     PASS
Config ID:             BK-CNF-01
Condition:             BASELINE
Model:                 qwen2.5:3b (Qwen-only)
Host Available RAM:    12.0000 GiB (Preflight requirement: 7.0 GiB)
Preflight Headroom:    PASS
Summary Output:        reports/phase_03f_r16_2_single_trial_summary.json
Traces Destination:    traces/phase_03f_r16_2
Zero validation errors detected. All structural and parameter safeguards verified.
To execute this single trial, re-run with: --execute-single-trial
================================================================================
ok
test_benign_configuration_is_not_applicable (scripts.test_phase_03f_single_trial_r16_2.TestR162EnhancedExposureReporting.test_benign_configuration_is_not_applicable)
Benign configurations report NOT_APPLICABLE. ... ok
test_co_occurring_target_and_payload_confirmed (scripts.test_phase_03f_single_trial_r16_2.TestR162EnhancedExposureReporting.test_co_occurring_target_and_payload_confirmed)
Single observation containing target and payload confirms exposure. ... ok
test_entity_only_is_unresolved_not_unexposed (scripts.test_phase_03f_single_trial_r16_2.TestR162EnhancedExposureReporting.test_entity_only_is_unresolved_not_unexposed)
Observing target entity alone without payload is ENTITY_ONLY_UNRESOLVED, NOT unexposed. ... ok
test_partial_distinctive_fragment_is_unresolved_not_unexposed (scripts.test_phase_03f_single_trial_r16_2.TestR162EnhancedExposureReporting.test_partial_distinctive_fragment_is_unresolved_not_unexposed)
Distinctive payload fragment observed without target is PARTIAL_PAYLOAD_UNRESOLVED, NOT unexposed. ... ok
test_split_observation_is_unresolved_not_unexposed (scripts.test_phase_03f_single_trial_r16_2.TestR162EnhancedExposureReporting.test_split_observation_is_unresolved_not_unexposed)
Target in one observation and payload in another is SPLIT_OBSERVATION_UNRESOLVED, NOT unexposed. ... ok
test_truly_unexposed_observations (scripts.test_phase_03f_single_trial_r16_2.TestR162EnhancedExposureReporting.test_truly_unexposed_observations)
Observations with zero payload fragments and zero target entities are UNEXPOSED. ... ok
test_preserves_all_proposals_and_arguments (scripts.test_phase_03f_single_trial_r16_2.TestR162FullProposalPreservation.test_preserves_all_proposals_and_arguments)
Evidence records all proposals and argument dicts rather than only the first. ... ok
test_overwrite_refusal (scripts.test_phase_03f_single_trial_r16_2.TestR162OutputPathProtectionAndSafetyThresholds.test_overwrite_refusal)
Refuse to overwrite existing summary file. ... ok
test_reserved_artifact_collision (scripts.test_phase_03f_single_trial_r16_2.TestR162OutputPathProtectionAndSafetyThresholds.test_reserved_artifact_collision)
Refuse paths colliding with historical reports. ... ok
test_threshold_constants_values (scripts.test_phase_03f_single_trial_r16_2.TestR162OutputPathProtectionAndSafetyThresholds.test_threshold_constants_values)
Calibrated thresholds are preserved. ... ok
test_coordinator_rejects_non_qwen (scripts.test_phase_03f_single_trial_r16_2.TestR162SingleTrialAndQwenEnforcement.test_coordinator_rejects_non_qwen)
Reject non-Qwen models at coordinator init. ... ok
test_stage2_check_after_setup_stops_monitor_and_refuses (scripts.test_phase_03f_single_trial_r16_2.TestR162Stage2PreflightAndMonitorShutdown.test_stage2_check_after_setup_stops_monitor_and_refuses)
Stage 2 check happens after setup; if < 7.0 GiB, stops monitor, records refusal, dispatches 0 trials. ... ok
test_evaluate_injection_exposure_without_trace (scripts.test_phase_03f_single_trial_r16_2.TestR162TrialFailureWithoutTraceRecord.test_evaluate_injection_exposure_without_trace)
Req 1: evaluate_injection_exposure on attacked config with trace=None returns UNRESOLVED_NO_TRACE. ... ok
test_trial_exception_sets_null_outcomes_and_incomplete_audit (scripts.test_phase_03f_single_trial_r16_2.TestR162TrialFailureWithoutTraceRecord.test_trial_exception_sets_null_outcomes_and_incomplete_audit)
Req 1, 2, 3: When coordinator.run_trial raises an exception (no trace): ... ok
test_unauthorized_call_with_low_ram_writes_zero_files (scripts.test_phase_03f_single_trial_r16_2.TestR162UnauthorizedApiCallNoSideEffects.test_unauthorized_call_with_low_ram_writes_zero_files)
Req 4: Even if available RAM < 7.0 GiB, an unauthorized API call raises ... ok

----------------------------------------------------------------------
Ran 17 tests in 0.151s

OK
```

---

## 4. Non-Executing Validation Verification

**Execution Command**:
```powershell
.\.venv\Scripts\python.exe scripts/run_phase_03f_single_trial_r16_2.py --config-id BK-CNF-01 --condition PROVENANCE_AWARE
```

**Output**:
```text
[SAFETY NOTICE] Runner invoked without --execute-single-trial.
Defaulting to non-executing validation mode. Zero model calls, zero AgentDojo executions.

================================================================================
PHASE 03F R16.2: SINGLE-TRIAL RUNNER VALIDATION REPORT
================================================================================
Validation Status:     PASS
Config ID:             BK-CNF-01
Condition:             PROVENANCE_AWARE
Model:                 qwen2.5:3b (Qwen-only)
Host Available RAM:    7.4011 GiB (Preflight requirement: 7.0 GiB)
Preflight Headroom:    PASS
Summary Output:        D:\multiagent_security_prov\Multiagent_security_prov\reports\phase_03f_r16_2_single_trial_summary.json
Traces Destination:    D:\multiagent_security_prov\Multiagent_security_prov\traces\phase_03f_r16_2
Zero validation errors detected. All structural and parameter safeguards verified.
To execute this single trial, re-run with: --execute-single-trial
================================================================================
```

---

## 5. Architectural Realities & Safety Governance

1. **No Absolute RAM Guarantee**:
   The Windows user-space architecture cannot guarantee that available host RAM will never dip below 3.0 GiB. Synchronous network socket reads (`recv()`) and synchronous Python tool executions cannot be preempted mid-instruction.
2. **Advisory Unload**:
   `POST /api/generate` with `keep_alive: 0` sends an advisory request to Ollama; it does not force immediate OS physical RAM recovery.
3. **Best-Effort Governance**:
   Safety is enforced via:
   - Stage 1 preflight (>= 7.0 GiB).
   - Stage 2 preflight post-setup (>= 7.0 GiB).
   - Continuous monitor with 5.0 GiB emergency stop.
   - Guarded downstream tool execution.
   - Non-compliant protocol violation classification (< 3.0 GiB).
4. **Research Prototype Purpose**:
   The runner is designed to execute at most one single trial under researcher supervision, recording all evidence accurately without overclaiming security guarantees or false-negative exposure outcomes.

---

## 6. Final Verdict

**Candidate Status**: **`READY FOR STATIC REVIEW`**
- All 4 specific R16.2 remediations implemented and verified.
- 17/17 dedicated mocked unit tests passing.
- Default CLI execution remains non-executing validation.
- Reference repository `D:\Agent_watch_prov` untouched.
- Historical candidates R8 through R16.1 preserved without modification.
- Zero live Ollama requests, zero AgentDojo executions, zero benchmark runs.
