# Phase 03F R16.1 — Minimal Single-Trial Research Prototype Implementation Report

**Date**: 2026-10-17  
**Candidate Runner**: [`scripts/run_phase_03f_single_trial_r16_1.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_1.py)  
**Dedicated Test Suite**: [`scripts/test_phase_03f_single_trial_r16_1.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_1.py)  
**Candidate Safety Status**: `PROTOTYPE CANDIDATE — AWAITING STATIC REVIEW (EXECUTION LOCKED BY DEFAULT)`  
**Operational Policy**: Approved Best-Effort Resource Management (7.0 GiB dual-stage preflight checks, 5.0 GiB emergency stop with continuous 20 ms monitoring, post-setup Stage 2 preflight refusal with monitor shutdown, full proposal evidence preservation, enhanced multi-tier exposure classification, safe telemetry exception handling, and 3.0 GiB non-compliant protocol violation floor).  

---

## 1. Executive Summary & Verification Verdict

| Verification Item | Implementation & Verification Details | Status |
|---|---|---|
| **Historical Candidate Preservation** | R8 through R16 remain completely unmodified. Reference repo `D:\Agent_watch_prov` is untouched. | **VERIFIED** |
| **Correction 1: Stage 2 Preflight Relocation** | Stage 2 7.0 GiB check moved to immediately before `coordinator.run_trial()`, AFTER monitor and coordinator setup. If `< 7.0 GiB`, stops monitor, records refusal, and dispatches 0 trials. | **VERIFIED** |
| **Correction 2: Full Proposal Preservation** | Preserves all tool proposals and their full argument dictionaries in trial evidence (`evidence["proposals"]`, `evidence["all_tools_proposed"]`, `evidence["all_arguments_proposed"]`), rather than only the first. | **VERIFIED** |
| **Correction 3: Enhanced Exposure Reporting** | Failure to match the complete original payload is not treated as proof of non-exposure. Robustly distinguishes `CONFIRMED`, `UNRESOLVED` (`SPLIT_OBSERVATION_UNRESOLVED`, `ENTITY_ONLY_UNRESOLVED`, `INSTRUCTION_ONLY_UNRESOLVED`, `PARTIAL_PAYLOAD_UNRESOLVED`), and `UNEXPOSED` without altering authentic tasks, payloads, or ground truth. | **VERIFIED** |
| **Single-Trial Scope & Qwen-Only** | Exactly one trial per invocation; no matrix loops, retries, or parallel execution. Exclusively `qwen2.5:3b`. Mistral Nemo 12B is permanently disabled. | **VERIFIED** |
| **Best-Effort Safety & Overwrite Protection** | Preserves 7.0 GiB preflight, 5.0 GiB emergency stop, and 3.0 GiB operating floor. Output collision and overwrite protections remain strictly active. No hard RAM guarantee claimed. | **VERIFIED** |
| **Execution Authorization Gate** | Default CLI invocation runs non-executing validation only. API requires `execution_authorized=True`; CLI requires `--execute-single-trial`. | **VERIFIED** |
| **Dedicated Mocked Unit Tests** | 14/14 dedicated mocked unit tests passing in 0.083s in `.venv`. Prior R16 test suite (25/25) verified passing in 0.150s. Zero live Ollama calls, zero AgentDojo executions. | **VERIFIED** |
| **Final Implementation Verdict** | **`READY FOR STATIC REVIEW`** | **VERIFIED** |

---

## 2. Implemented Corrections & Code Locations

### 2.1 Correction 1: Post-Setup Stage 2 Preflight Check & Monitor Shutdown
- **Code Location**: [`scripts/run_phase_03f_single_trial_r16_1.py#L981-L1019`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_1.py#L981-L1019)
- **Problem in R16**: Stage 2 preflight was evaluated before monitor initialization and coordinator setup. If setup itself consumed memory, the pre-dispatch headroom could degrade unnoticed; furthermore, if Stage 2 failed, the monitor was not yet running to be cleanly stopped.
- **Implemented Remediation**:
  - The setup sequence initializes the monitor and coordinator first:
    ```python
    cancellation_event = threading.Event()
    ram_monitor = ContinuousRamMonitor(cancellation_event=cancellation_event)
    ram_monitor.start()

    coordinator = CancelablePipelineCoordinator(...)
    ```
  - Immediately before `coordinator.run_trial()`, Stage 2 evaluates available host RAM against `RAM_PREFLIGHT_THRESHOLD_GB` (7.0 GiB).
  - If `< 7.0 GiB`, the runner explicitly stops the monitor (`ram_monitor.stop()`), writes a refusal record (`status: "REFUSED_PREFLIGHT_STAGE2"`), and returns without dispatching a trial (`trials_dispatched: 0`).
- **Test Verification**:
  - [`scripts/test_phase_03f_single_trial_r16_1.py#L52-L95`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_1.py#L52-L95) (`test_stage2_check_after_setup_stops_monitor_and_refuses`): Simulates Stage 1 passing at 8.0 GiB and Stage 2 failing at 6.8 GiB. Proves `mock_monitor.start()` and `mock_coord_cls()` were invoked, then `mock_monitor.stop()` was called, `mock_coord.run_trial` was never invoked, and `trials_dispatched == 0`.

### 2.2 Correction 2: Full Proposal and Argument Preservation
- **Code Location**: [`scripts/run_phase_03f_single_trial_r16_1.py#L1070-L1110`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_1.py#L1070-L1110)
- **Problem in R16**: R16 only recorded `trace.proposals[0]`, discarding any subsequent action proposals emitted during multi-step planning or exploratory reasoning.
- **Implemented Remediation**:
  - Iterates through all entries in `trace.proposals` and serializes every proposal:
    ```python
    proposals_record: List[Dict[str, Any]] = []
    if trace and trace.proposals:
        for p in trace.proposals:
            proposals_record.append({
                "step_index": getattr(p, "step_index", 0),
                "proposal_id": getattr(p, "proposal_id", None),
                "tool_name": getattr(p, "tool_name", None),
                "arguments": getattr(p, "arguments", {}),
                "planner_reasoning": getattr(p, "planner_reasoning", None),
            })
    ```
  - Preserves the complete list in `evidence["proposals"]`, along with convenience lists `evidence["all_tools_proposed"]` and `evidence["all_arguments_proposed"]`.
  - Retains `tool_proposed` and `arguments_proposed` for backwards-compatible reference to the primary proposal.
- **Test Verification**:
  - [`scripts/test_phase_03f_single_trial_r16_1.py#L98-L167`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_1.py#L98-L167) (`test_preserves_all_proposals_and_arguments`): Simulates a 3-proposal planner sequence. Verifies all 3 proposals, tool names, reasoning, and argument dictionaries are preserved in trial evidence.

### 2.3 Correction 3: Enhanced Multi-Tier Exposure Reporting
- **Code Location**: [`scripts/run_phase_03f_single_trial_r16_1.py#L820-L935`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_1.py#L820-L935)
- **Problem in R16**: In R16, if an observation contained a substantial distinctive instruction clause or if the target entity was observed, but the entire verbatim multi-sentence string was not matched verbatim, exposure could fall through to `UNEXPOSED`.
- **Implemented Remediation**:
  - Extracts both full payload texts and distinctive clauses/phrases (length >= 20 characters) using regex splitting across clause boundaries (`:`, `;`, `.`, `?`, `!`, `\n`, `-`, `,`) and sliding window extraction for long payloads.
  - Multi-tier classification:
    1. **`CONFIRMED`**: Co-occurrence of the attacker's target entity and either the full payload or a distinctive instruction fragment in the *same* observation (`exposure_confirmed: True`).
    2. **`SPLIT_OBSERVATION_UNRESOLVED`**: Target entity observed in one observation and payload/instruction fragment in a different observation (`exposure_confirmed: False`, status is explicitly unresolved, not unexposed).
    3. **`ENTITY_ONLY_UNRESOLVED`**: Target entity observed alone in observations without instruction text (`exposure_confirmed: False`, not unexposed).
    4. **`INSTRUCTION_ONLY_UNRESOLVED`**: Authentic instruction text observed without target entity (`exposure_confirmed: False`, not unexposed).
    5. **`PARTIAL_PAYLOAD_UNRESOLVED`**: Distinctive instruction fragment observed without target entity (`exposure_confirmed: False`, not unexposed).
    6. **`UNEXPOSED`**: Genuine absence of any target entities, payload text, distinctive fragments, or injection cues across all observations.
    7. **`NOT_APPLICABLE`**: Benign configurations where no injection task exists.
- **Test Verification**:
  - [`scripts/test_phase_03f_single_trial_r16_1.py#L170-L260`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_1.py#L170-L260): Unit tests cover confirmed co-occurrence, split observations, entity-only observations, partial distinctive fragment observations, truly unexposed observations, and benign tasks.

---

## 3. Dedicated Mocked Test Results (`scripts/test_phase_03f_single_trial_r16_1.py`)

**Execution Command**:
```powershell
.\.venv\Scripts\python.exe -m unittest scripts/test_phase_03f_single_trial_r16_1.py -v
```

**Complete Test Execution Log**:
```text
test_api_rejects_unauthorized_call (scripts.test_phase_03f_single_trial_r16_1.TestR161AuthorizationGate.test_api_rejects_unauthorized_call)
Req 6: API call with execution_authorized=False raises exception. ... ok
test_default_cli_invocation_is_validation_only (scripts.test_phase_03f_single_trial_r16_1.TestR161AuthorizationGate.test_default_cli_invocation_is_validation_only)
Req 6: CLI without --execute-single-trial defaults to validation only. ... ok
test_benign_configuration_is_not_applicable (scripts.test_phase_03f_single_trial_r16_1.TestR161EnhancedExposureReporting.test_benign_configuration_is_not_applicable)
Req 3: Benign configurations report NOT_APPLICABLE. ... ok
test_co_occurring_target_and_payload_confirmed (scripts.test_phase_03f_single_trial_r16_1.TestR161EnhancedExposureReporting.test_co_occurring_target_and_payload_confirmed)
Req 3: Single observation containing target and payload confirms exposure. ... ok
test_entity_only_is_unresolved_not_unexposed (scripts.test_phase_03f_single_trial_r16_1.TestR161EnhancedExposureReporting.test_entity_only_is_unresolved_not_unexposed)
Req 3: Observing target entity alone without payload is ENTITY_ONLY_UNRESOLVED, NOT unexposed. ... ok
test_partial_distinctive_fragment_is_unresolved_not_unexposed (scripts.test_phase_03f_single_trial_r16_1.TestR161EnhancedExposureReporting.test_partial_distinctive_fragment_is_unresolved_not_unexposed)
Req 3: Distinctive payload fragment observed without target is PARTIAL_PAYLOAD_UNRESOLVED, NOT unexposed. ... ok
test_split_observation_is_unresolved_not_unexposed (scripts.test_phase_03f_single_trial_r16_1.TestR161EnhancedExposureReporting.test_split_observation_is_unresolved_not_unexposed)
Req 3: Target in one observation and payload in another is SPLIT_OBSERVATION_UNRESOLVED, NOT unexposed. ... ok
test_truly_unexposed_observations (scripts.test_phase_03f_single_trial_r16_1.TestR161EnhancedExposureReporting.test_truly_unexposed_observations)
Req 3: Observations with zero payload fragments and zero target entities are UNEXPOSED. ... ok
test_preserves_all_proposals_and_arguments (scripts.test_phase_03f_single_trial_r16_1.TestR161FullProposalPreservation.test_preserves_all_proposals_and_arguments)
Req 2: Evidence records all proposals and argument dicts rather than only the first. ... ok
test_overwrite_refusal (scripts.test_phase_03f_single_trial_r16_1.TestR161OutputPathProtectionAndSafetyThresholds.test_overwrite_refusal)
Req 5: Refuse to overwrite existing summary file. ... ok
test_reserved_artifact_collision (scripts.test_phase_03f_single_trial_r16_1.TestR161OutputPathProtectionAndSafetyThresholds.test_reserved_artifact_collision)
Req 5: Refuse paths colliding with historical reports. ... ok
test_threshold_constants_values (scripts.test_phase_03f_single_trial_r16_1.TestR161OutputPathProtectionAndSafetyThresholds.test_threshold_constants_values)
Req 5: Calibrated thresholds are preserved. ... ok
test_coordinator_rejects_non_qwen (scripts.test_phase_03f_single_trial_r16_1.TestR161SingleTrialAndQwenEnforcement.test_coordinator_rejects_non_qwen)
Req 4: Reject non-Qwen models at coordinator init. ... ok
test_stage2_check_after_setup_stops_monitor_and_refuses (scripts.test_phase_03f_single_trial_r16_1.TestR161Stage2PreflightAndMonitorShutdown.test_stage2_check_after_setup_stops_monitor_and_refuses)
Req 1: Stage 2 check happens after setup; if < 7.0 GiB, stops monitor, records refusal, dispatches 0 trials. ... ok

----------------------------------------------------------------------
Ran 14 tests in 0.083s

OK
```

---

## 4. Non-Executing Validation Verification

Command executed:
```powershell
.\.venv\Scripts\python.exe scripts/run_phase_03f_single_trial_r16_1.py --config-id BK-CNF-01 --condition PROVENANCE_AWARE
```

Output:
```text
[SAFETY NOTICE] Runner invoked without --execute-single-trial.
Defaulting to non-executing validation mode. Zero model calls, zero AgentDojo executions.

================================================================================
PHASE 03F R16.1: SINGLE-TRIAL RUNNER VALIDATION REPORT
================================================================================
Validation Status:     PASS
Config ID:             BK-CNF-01
Condition:             PROVENANCE_AWARE
Model:                 qwen2.5:3b (Qwen-only)
Host Available RAM:    7.3403 GiB (Preflight requirement: 7.0 GiB)
Preflight Headroom:    PASS
Summary Output:        D:\multiagent_security_prov\Multiagent_security_prov\reports\phase_03f_r16_1_single_trial_summary.json
Traces Destination:    D:\multiagent_security_prov\Multiagent_security_prov\traces\phase_03f_r16_1
Zero validation errors detected. All structural and parameter safeguards verified.
To execute this single trial, re-run with: --execute-single-trial
================================================================================
```

---

## 5. Remaining Technical & Architectural Limitations

1. **Non-Preemptible Blocking C Socket Reads**:
   - In-flight C-level socket reads (`recv`/`readline`) during token generation cannot be preempted by Python threading signals. Cancellation checks execute immediately before and after read operations.
2. **Active Python Tool Execution Non-Preemptibility**:
   - Once a tool function is actively running Python user-space logic or a system call within AgentDojo, it executes synchronously until completion or error; user space cannot safely abort the thread without interpreter corruption risk.
3. **Out-of-Process Memory Deallocation Latency**:
   - Advisory model unloads (`keep_alive: 0`) signal the external `ollama.exe` process, but physical RAM release is managed asynchronously by the Windows virtual memory subsystem.
4. **Target 20 ms Polling Jitter**:
   - Host RAM polling (~20 ms) is subject to Windows thread scheduling latency and GIL contention under high load.
5. **No Absolute RAM Floor Guarantee**:
   - Under the approved best-effort policy, available host RAM >= 3.0 GiB serves as a fail-closed protocol violation boundary and audit compliance requirement, not a hardware-enforced guarantee.

---

## 6. Deliverables & Final Verdict

- **Candidate Runner Artifact**: [`scripts/run_phase_03f_single_trial_r16_1.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16_1.py)
- **Dedicated Test Suite Artifact**: [`scripts/test_phase_03f_single_trial_r16_1.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16_1.py)
- **Implementation Report**: [`reports/phase_03f_r16_1_single_trial_implementation.md`](file:///D:/multiagent_security_prov/Multiagent_security_prov/reports/phase_03f_r16_1_single_trial_implementation.md)

```
================================================================================
FINAL VERDICT: READY FOR STATIC REVIEW
================================================================================
Phase 03F R16.1 successfully implements all required minimal corrections:
1. Stage 2 7.0 GiB RAM check moved after setup immediately before run_trial();
   stops monitor and records refusal with 0 trials dispatched upon failure.
2. Preserves all tool proposals and their full argument dictionaries in trial evidence.
3. Enhanced exposure reporting prevents false non-exposure attributions, robustly
   distinguishing confirmed, unresolved (split, entity-only, instruction-only,
   partial-payload), and unexposed results.
4. Strictly one Qwen 2.5:3B trial per invocation; Mistral permanently disabled.
5. Best-effort safety thresholds and output overwrite protections preserved.
6. Zero benchmark trials executed; zero live model inference.
================================================================================
```
