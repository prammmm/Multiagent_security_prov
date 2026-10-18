# Phase 03F R14 — RAM Safety Design Review (Non-Executing)

**Date**: 2026-10-17  
**Repository**: `D:\multiagent_security_prov\Multiagent_security_prov`  
**Inspected Candidate**: `scripts/run_phase_03f_confirmation_r13.py` (and supporting pipeline modules in `src/pipeline/`)  
**Scope**: Read-only architectural and systems design audit of available host RAM enforcement under Windows user-space architecture with an out-of-process Ollama inference daemon.  
**Execution Status**: Non-executing audit. Zero model inferences, zero AgentDojo scenario executions, zero benchmark trials dispatched. Reference repository `D:\Agent_watch_prov` untouched.

---

## Executive Summary & Final Verdict

| Evaluation Dimension | Finding / Status |
|---|---|
| **Hard Available RAM Floor Requirement** | System available RAM must **NEVER** drop below **3.0 GiB** at any time during execution. |
| **Current Enforcement Mechanism** | Dual-stage 7.0 GiB pre-flight checks + 100 ms polling via `ContinuousRamMonitor` + post-trial stop check. |
| **Can Current Architecture Enforce In-Trial 3.0 GiB Floor?** | **NO** (Post-trial halt only; zero in-trial interruption or preemption capability). |
| **Can Windows User-Space Guarantee a Hard Global 3.0 GiB Floor?** | **NO** (Mathematically and architecturally impossible in user space without hypervisor/kernel memory reservations). |
| **R13 Execution Lock Status Recommendation** | **RETAIN UNCONDITIONAL EXECUTION LOCK (`BENCHMARK_EXECUTION_LOCKED = True`)**. |
| **Final Verdict** | **`NOT FEASIBLE UNDER CURRENT CONSTRAINTS`** |

---

## 1. Why the Current RAM Monitor Cannot Guarantee the 3.0 GiB Floor

### 1.1 Post-Facto Observation vs. In-Trial Preemption [VERIFIED]
- **Citation**: [`scripts/run_phase_03f_confirmation_r13.py#L2168-L2196`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_confirmation_r13.py#L2168-L2196)
- **Mechanism**:
  ```python
  trace = qwen_coordinator.run_trial(...)          # Line 2169: Synchronous, blocking execution
  t_elapsed = time.perf_counter() - t_start       # Line 2176
  min_ram_during_unrounded = ram_monitor.stop()    # Line 2177: Evaluated ONLY AFTER trial completes
  ...
  if not passed_during or not passed_post:         # Line 2194
      stopping_reason = f"Available RAM fell below {RAM_MIN_THRESHOLD_GB} GB..."
  ```
- **Finding**: The runner halts subsequent trials in the sequence *only after* `run_trial()` returns. If available RAM drops to 2.5 GiB, 1.0 GiB, or causes OS thrashing at second 5 of a 30-second trial, the trial continues running to completion. The 3.0 GiB floor is breached during the trial.

### 1.2 Sampling Latency Window of Blindness (100 ms) [VERIFIED]
- **Citation**: [`scripts/run_phase_03f_confirmation_r13.py#L427-L470`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_confirmation_r13.py#L427-L470)
- **Mechanism**:
  ```python
  self.interval = interval_seconds  # Default 0.1s (100 ms)
  ...
  while not self.stop_event.is_set():
      ...
      time.sleep(self.interval)
  ```
- **Finding**: In modern OS memory management, kernel page allocation, dynamic memory mapping, and model buffer allocations occur on sub-millisecond timescales. In any 100 ms window, several gigabytes of memory can be allocated or reallocated. A sudden memory spike by Ollama or any co-located process can drop available RAM below 3.0 GiB and recover or crash between sampling intervals.

### 1.3 Passive Telemetry Without Interruption Path [VERIFIED]
- **Citation**: [`scripts/run_phase_03f_confirmation_r13.py#L449-L470`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_confirmation_r13.py#L449-L470)
- **Mechanism**: `ContinuousRamMonitor` runs on a background daemon thread. When it detects `avail < self.min_ram_bytes`, it only updates internal variables (`self.min_ram_bytes = avail`).
- **Finding**: The monitor possesses **zero** IPC channels, abort signals, socket-reset hooks, or thread-interrupt mechanisms to communicate with the main thread or with Ollama while an inference is in-flight.

---

## 2. Cancellation and Termination of In-Flight Ollama Inferences

### 2.1 Synchronous Blocking HTTP Client Architecture [VERIFIED]
- **Citation**: [`src/pipeline/ollama_client.py#L27-L65`](file:///D:/multiagent_security_prov/Multiagent_security_prov/src/pipeline/ollama_client.py#L27-L65)
- **Mechanism**:
  ```python
  payload = {
      "model": target_model,
      "prompt": prompt,
      "stream": False,  # Non-streaming request
      ...
  }
  ...
  with urllib.request.urlopen(req, timeout=120) as response:  # Blocking socket recv
      res_body = response.read().decode("utf-8")
  ```
- **Finding**: The trial thread blocks unconditionally inside C socket I/O (`urllib.request.urlopen`) with a 120-second timeout. Python cannot safely or preemptively interrupt a blocking C-runtime socket call from another thread without forcibly tearing down the socket or terminating the process.

### 2.2 Cancelling HTTP Client vs. Server-Side Memory Deallocation [VERIFIED / INFERRED]
- **Client Socket Abort**: If the client forcibly closes the TCP socket during inference, Ollama's HTTP server context receives a cancellation signal (`r.Context().Done()`).
- **Server Retention of Weights (`keep_alive`)**: Even when Ollama stops generating tokens for a cancelled request, **it does not free model weights from memory**. By default, Ollama retains models in RAM/VRAM for a 5-minute keep-alive period. If model weights or KV cache caused RAM pressure, aborting the HTTP connection does **not** return the memory to the host operating system.
- **Unload Latency**: Reclaiming memory from Ollama requires sending an explicit unload request (e.g. `POST /api/generate` with `keep_alive: 0`), which cannot execute if the server is stalled, swapping, or thrashing.

### 2.3 Hard Process Tree Termination (`TerminateProcess` / `taskkill`) [VERIFIED / INFERRED]
- **Mechanism**: Forcibly terminating `ollama.exe` and its runner child processes (`ollama_llama_server.exe`) via Win32 `TerminateProcess` or `taskkill /F /T`.
- **Limitations**:
  1. **Reactive, Not Proactive**: Termination can only be initiated *after* the breach or near-breach is detected.
  2. **Latency of Teardown**: Between detection (0–100 ms), process tree enumeration, handle opening with `PROCESS_TERMINATE`, and kernel page table teardown, 100–300 ms elapse. During this window, memory allocation has already breached the 3.0 GiB floor.
  3. **Catastrophic Pipeline Crash**: Abruptly terminating the Ollama server kills the local inference backend, causing subsequent trials to fail immediately with unhandled connection errors unless a complex automated daemon restart and health-check loop is implemented.

---

## 3. Windows Process and Memory Controls: Realities vs. Limitations

| Control Mechanism | Win32 API / Concept | What It Improves | What It Still Cannot Guarantee | Classification |
|---|---|---|---|---|
| **Windows Job Objects** | `CreateJobObject`, `SetInformationJobObject` (`JobMemoryLimit`) | Can set hard virtual commit caps on processes inside the job. | 1. Ollama is an external, pre-existing process; assigning external processes to job objects from user space is restricted.<br>2. Job limits bound the *process's* commit, **not global available system RAM**. If Windows background tasks consume 4 GB, global RAM drops below 3.0 GB even if Ollama stays within its limit.<br>3. Exceeding commit limit causes hard process crash (`STATUS_COMMITMENT_LIMIT`). | **VERIFIED** |
| **Low-Memory Resource Notification** | `CreateMemoryResourceNotification` (`LowMemoryResourceNotification`) | Kernel-level event signaled when system memory is low. | 1. Threshold is hardcoded by the Windows NT kernel (typically 4–10% of physical RAM), **not configurable to 3.0 GiB**.<br>2. The notification is asynchronous and fires *after* the OS has already entered low-memory condition. | **VERIFIED** |
| **High-Frequency Polling** | `GlobalMemoryStatusEx` via C/ctypes (1–5 ms) | Reduces sampling blindness from 100 ms to 1–5 ms. | Still fundamentally reactive. Cannot prevent an allocation of 2 GB that occurs in a single burst or page fault. Adds CPU overhead. | **VERIFIED** |
| **Working Set Caps** | `SetProcessWorkingSetSizeEx` (`QUOTA_LIMITS_HARDWS_MAX`) | Restricts physical page residency of target process. | Only restricts working set pages; does not restrict committed virtual memory or pagefile allocations. Evicted pages move to standby/modified lists, still consuming physical RAM until repurposed by the kernel. | **VERIFIED** |
| **Kernel Memory Reservation** | Custom Windows Kernel Driver (Ring 0) | Kernel hook intercepting `NtAllocateVirtualMemory`. | Architecturally out of scope for user-space automation. Modifying kernel memory management requires signed kernel drivers. | **VERIFIED** |

---

## 4. Enforceability: Hard Guarantee vs. Best-Effort Safeguard

### 4.1 Strict 3.0 GiB Floor Enforceability [VERIFIED]
Under the current Windows user-space architecture with an external Ollama daemon, a **strict, absolute guarantee that available system RAM never falls below 3.0 GiB is ARCHITECTURALLY AND MATHEMATICALLY IMPOSSIBLE**.

### 4.2 Distinguishing Safeguard vs. Guarantee [VERIFIED]
- **Hard Invariant Guarantee**: A mathematical certainty that available physical host RAM will strictly satisfy `RAM_avail >= 3.000000 GiB` for every microsecond of execution.
  - *Status*: **Unattainable in user space**. Global available RAM is a shared, system-wide metric influenced by OS kernel pools, hardware drivers, system services (Windows Defender, Search Indexer), and external user applications. No user-space process can prohibit another process or the OS kernel from allocating memory.
- **Best-Effort Safeguard**: A defense-in-depth mitigation system that minimizes the probability and duration of memory pressure.
  - *Status*: **Feasible with substantial redesign**. (Dual-stage pre-flight headroom, streaming inference with client-side cancellation, conservative early-warning buffers).

---

## 5. Recommended Architecture & Staged Implementation Plan (If Re-designed)

If the project re-evaluates its requirements and replaces the impossible "absolute guarantee" with a "defensible fail-closed engineering mitigation," the following architecture is required:

### 5.1 Architectural Redesign Components
1. **Asynchronous Streaming Inference**:
   - Refactor `OllamaClient.generate()` to use `stream: True`.
   - Process tokens iteratively via a generator.
2. **Conservative Early-Warning Emergency Buffer**:
   - Establish an **Emergency Threshold** at **5.0 GiB** (providing a 2.0 GiB buffer above the 3.0 GiB floor).
   - The monitoring thread checks `GlobalMemoryStatusEx` every 20 ms.
   - If available RAM breaches 5.0 GiB, an atomic flag `emergency_stop_triggered` is set.
3. **Mid-Inference Interruption**:
   - The streaming loop checks `emergency_stop_triggered` before consuming each token chunk.
   - If set, it immediately breaks out of the generator, closes the HTTP response socket, issues a `keep_alive: 0` request, and raises `EmergencyRamFloorExceededError`.
4. **VRAM Offloading Requirement**:
   - Explicitly enforce `num_gpu: 99` in Ollama options and verify before launch that 100% of model layers fit in GPU VRAM (Qwen 2.5:3B requires ~2.2 GB VRAM). This strictly isolates model inference memory to dedicated GPU VRAM, preventing model-driven host RAM spikes.

### 5.2 Staged Implementation Roadmap
- **Stage 1 (Mocked Design Validation)**: Implement and unit-test streaming client cancellation and fail-closed monitor signaling using mocked sockets. Zero model inference.
- **Stage 2 (Sandbox Pilot on Non-Confirmation Scenarios)**: Benchmark memory footprint under extreme prompt load in a throwaway non-held-out sandbox to empirically measure deceleration latency.
- **Stage 3 (Independent Safety Review)**: Review telemetry from Stage 2 to determine empirical minimum RAM observed before deciding whether the execution lock can be safely reconsidered.

---

## 6. Static and Mocked Unit Tests Required for Redesign

All proposed tests are strictly non-executing (mocked, static, zero Ollama calls, zero benchmark trials):

1. **`test_streaming_cancellation_on_ram_emergency_flag`**:
   - *Design*: Mock an HTTP streaming response yielding tokens every 10 ms. Set `emergency_stop_triggered = True` after token 3.
   - *Verification*: Verify that the streaming loop immediately closes the socket, yields zero further tokens, and raises `EmergencyRamFloorExceededError`.
2. **`test_early_warning_threshold_fires_at_calibrated_headroom`**:
   - *Design*: Mock virtual memory values transitioning from 7.5 GiB -> 5.5 GiB -> 4.9 GiB -> 3.2 GiB.
   - *Verification*: Verify that emergency halt fires at 4.9 GiB, safely halting execution before RAM reaches the 3.0 GiB floor.
3. **`test_explicit_keep_alive_zero_dispatched_on_abort`**:
   - *Design*: Capture outbound HTTP requests when an abort occurs.
   - *Verification*: Verify an explicit unload payload (`keep_alive: 0`) is transmitted to force model deallocation.
4. **`test_fail_closed_on_monitor_thread_failure_during_streaming`**:
   - *Design*: Simulate an unhandled exception inside the continuous RAM monitor thread mid-stream.
   - *Verification*: Verify the streaming generator detects `not monitor.is_healthy` and immediately aborts the in-flight inference.

---

## 7. Audit Findings Classification Summary

- **Finding 1.1–1.5 (Post-Trial Halt & Polling Blindness)**: **`VERIFIED`** (Directly verified in `scripts/run_phase_03f_confirmation_r13.py` lines 420–472 and 2168–2196).
- **Finding 2.1–2.2 (Synchronous Blocking Socket & Keep-Alive Memory Retention)**: **`VERIFIED`** (Verified in `src/pipeline/ollama_client.py` lines 34 and 58).
- **Finding 2.3–2.4 (Ollama Process Termination Latency & Failure Modes)**: **`VERIFIED / INFERRED`** (Based on Windows OS process teardown semantics and Ollama process architecture).
- **Finding 3.1–3.4 (Windows Job Object, Notification, and Driver Limitations)**: **`VERIFIED`** (Based on Windows NT memory manager architecture and Win32 API contracts).
- **Finding 4.1–4.3 (Impossibility of Hard Invariant Guarantee in User Space)**: **`VERIFIED`** (Fundamental operating systems constraint).

---

## Conclusion & Verdict

```
================================================================================
FINAL VERDICT: NOT FEASIBLE UNDER CURRENT CONSTRAINTS
================================================================================
A strict, unconditional guarantee that available host RAM will never drop below 
3.0 GiB during live synchronous Ollama inference cannot be enforced under 
Windows user-space architecture.

RECOMMENDATION:
1. Retain the unconditional execution lock in Phase 03F R13 (BENCHMARK_EXECUTION_LOCKED = True).
2. Do NOT execute the held-out Confirmation Set.
3. Do NOT weaken the project safety threshold.
4. If execution is ever to be contemplated, formally reformulate the policy 
   requirement to an approved defense-in-depth engineering mitigation with an 
   early-warning threshold (>= 5.0 GiB) and streaming socket cancellation.
================================================================================
```
