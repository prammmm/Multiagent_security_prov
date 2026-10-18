# Phase 00 — Environment Audit Report

**Date:** 2026-10-16  
**Project Workspace:** `D:\multiagent_security_prov\Multiagent_security_prov`  
**Reference Repository:** `D:\Agent_watch_prov` (Read-Only)  
**Hardware Platform:** AMD Ryzen 7 5800H (8C/16T), NVIDIA GeForce RTX 3060 Laptop GPU (6,144 MiB / 6 GB VRAM, Driver 616.92)  
**Evaluation Model Target:** `qwen2.5:3b` (via local Ollama server, zero cloud expenditure)  

---

## 1. Phase Objective

The objective of Phase 00 is to establish an audited, reproducible experimental environment for the **Direction B Multi-Agent Security Prototype** without altering the reference repository (`D:\Agent_watch_prov`), without duplicating model weights on disk, and with verified hardware GPU acceleration on the NVIDIA RTX 3060 Laptop GPU.

---

## 2. Work Completed

1. **Workspace Verification & Git State Audit:**
   - Verified that `D:\multiagent_security_prov\Multiagent_security_prov` is an established Git repository on branch `main` at commit `4b1275b` ("Initial commit").
   - Preserved `.gitattributes` and verified that no uncommitted changes were overwritten.
   - Created a strict `.gitignore` to prevent tracking of `.venv/`, Python bytecode, large models, logs, and sensitive credentials.
   - Initialized the required `reports/` directory.

2. **Hardware & Resource Verification:**
   - **CPU:** AMD Ryzen 7 5800H with Radeon Graphics (16 logical processors).
   - **System RAM:** 16,101,444 KB (~15.35 GB total), with 5,007,848 KB (~4.78 GB) free at baseline.
   - **Storage:** Drive `D:\` has **61.10 GB free space** out of 146.49 GB total capacity.
   - **GPU:** Dedicated NVIDIA GeForce RTX 3060 Laptop GPU (6,144 MiB VRAM), Driver Version 616.92, CUDA 11.8 / 13.4 UMD compatible.

3. **Ollama Service, Storage, and Model Inventory:**
   - Ollama process is actively running (PID 23904) listening at `http://127.0.0.1:11434`.
   - Verified model storage configuration: Models reside in `D:\ollama_models` (configured via `OLLAMA_MODELS="D:\ollama_models"`), preventing bloat on Drive C.
   - Audited existing models via `ollama list`:
     - `qwen2.5:3b` (Manifest ID `357c53fb659c`, 1.9 GB on disk) — **Primary evaluation model for Direction B**.
     - `llama3.2:3b` (Manifest ID `a80c4f17acd5`, 2.0 GB on disk).
     - `mistral-nemo:12b-instruct-2407-q4_K_M` (Manifest ID `daf673741712`, 7.5 GB on disk).
   - **Zero Duplicate Weights:** Confirmed that no new model weights need to be downloaded or copied.

4. **Live Model Smoke Test & GPU Offload Verification:**
   - Conducted an automated inference smoke test against `http://127.0.0.1:11434/api/generate` with prompt `"Say hello in 3 words."` on `qwen2.5:3b`.
   - Result: Model generated response `"Hello there."` in 4.41s total load+generation time (evaluation duration: 0.063s, 4 tokens).
   - Inspected `ollama ps`:
     - `qwen2.5:3b` loaded into memory: Size `2.2 GB`, **`PROCESSOR: 100% GPU`**, context length 4,096.
   - Inspected `nvidia-smi`:
     - GPU process `ollama\llama-server.exe` (PID 7532) actively holding memory in VRAM.
     - VRAM usage: 2,777 MiB / 6,144 MiB (45.2% total GPU memory used, including OS display overhead).
     - GPU utilization: 19% active compute, P8 power state (22W).
   - **Conclusion:** GPU inference acceleration on the RTX 3060 is **empirically verified**.

5. **Python Environment & Isolated `.venv` Setup:**
   - System Python version: **Python 3.11.0** (`C:\Users\Param\AppData\Local\Programs\Python\Python311\python.exe`).
   - Created dedicated virtual environment at `D:\multiagent_security_prov\Multiagent_security_prov\.venv` using `--system-site-packages`.
   - Verified package availability inside `.venv`:
     - `torch`: **2.7.1+cu118** (`torch.cuda.is_available() == True`, Device: `NVIDIA GeForce RTX 3060 Laptop GPU`).
     - `agentdojo`: **0.1.35** (benchmark suite `v1` available).
     - `openai`: **3.28.0** (standard client library for Ollama API interaction).
     - `pydantic`: **2.14.0** (data contracts & serialization).
     - `numpy`: **2.3.2**; `pandas`: **2.3.1**; `scikit-learn`: **1.7.1**.
   - Zero additional package downloads or redundant installations required.

6. **Inspection of Reference Repository (`D:\Agent_watch_prov`):**
   - Examined the reference repository in strict read-only mode.
   - Identified reusable, high-fidelity components to adapt into Direction B:
     1. **Trace Normalization & Event Schemas:** `agentwatch.traces.schema` (`RawExecutionRecord`, `RawStep`, `RawToolCall`, `RawToolResult`).
     2. **Integrity & Content Hashing:** `agentwatch.traces.integrity` (`compute_content_hash`, `verify_run_integrity`).
     3. **AgentDojo Harness Wrappers:** `agentwatch.benchmark.pilot_harness` (environment reset, user prompt injection, deterministic observation logging).
     4. **Provenance Tracking Utilities:** `agentwatch.features.provenance` (string overlap, token Jaccard, normalized argument substring matching).
     5. **Ground-Truth Matcher:** `agentwatch.benchmark.ground_truth_matcher` (exact tool-call parameter normalization).

---

## 3. Files Created or Modified

| File Path | Action | Description |
|---|---|---|
| `D:\multiagent_security_prov\Multiagent_security_prov\.gitignore` | Created | Git ignore rules for `.venv`, cache, model blobs, and logs |
| `D:\multiagent_security_prov\Multiagent_security_prov\reports\` | Created | Report directory for phase milestone documents |
| `D:\multiagent_security_prov\Multiagent_security_prov\reports\phase_00_environment_audit.md` | Created | Phase 00 definitive environment audit report |
| `D:\multiagent_security_prov\Multiagent_security_prov\.venv\` | Created | Dedicated virtual environment referencing Python 3.11 with PyTorch CUDA |

*Note: Zero files in `D:\Agent_watch_prov` were modified, moved, or deleted.*

---

## 4. Design Decisions and Rationale

1. **Virtual Environment with `--system-site-packages`:**
   - *Rationale:* The machine already has PyTorch 2.7.1+cu118 (CUDA 11.8) and `agentdojo==0.1.35` installed in Python 3.11. By creating the dedicated `.venv` at `D:\multiagent_security_prov\Multiagent_security_prov\.venv` with `--system-site-packages`, we avoid re-downloading gigabytes of CUDA binaries and wheel files, saving disk space while maintaining an isolated environment path.
2. **Direct Ollama HTTP `/api/generate` and `/v1` Endpoint Usage:**
   - *Rationale:* Ollama runs locally on port 11434 with models already resident in `D:\ollama_models`. Calling this local endpoint via standard HTTP / `openai` client ensures zero network dependencies and exact parity with the verified local runtime.
3. **Strict Model Freezing on `qwen2.5:3b`:**
   - *Rationale:* `qwen2.5:3b` is fully verified to load 100% of its layers into the RTX 3060 GPU VRAM (using ~2.2 GB of 6 GB), leaving ample headroom for Windows display buffers and prompt KV caching without triggering CPU offload bottlenecks.

---

## 5. Commands Executed and Verification Results

| Command Line | Purpose | Observed Output / Result |
|---|---|---|
| `git status` | Verify Git workspace state | Branch `main`, working tree clean, commit `4b1275b` |
| `Get-PSDrive D` | Verify disk space | Total Free: **61.10 GB** |
| `Get-CimInstance Win32_OperatingSystem` | Verify system RAM | Total: 15.35 GB, Free: ~4.78 GB |
| `ollama list` | List installed models | `qwen2.5:3b` (1.9 GB), `llama3.2:3b` (2.0 GB), `mistral-nemo:12b` (7.5 GB) |
| `ollama ps` (before test) | Verify loaded models | No active models resident |
| `python -c "urllib.request..."` | Smoke test inference on `qwen2.5:3b` | Response `"Hello there."`, 4.41s total, 4 tokens |
| `ollama ps` (after test) | Check offload status | `qwen2.5:3b`: Size 2.2 GB, **100% GPU**, context 4096 |
| `nvidia-smi` | Verify hardware VRAM & process | PID 7532 `llama-server.exe`, 2,777 MiB / 6,144 MiB VRAM allocated |
| `python -m venv .venv --system-site-packages` | Create isolated environment | `.venv` created cleanly |
| `.venv\Scripts\python.exe -c "import torch..."` | Verify packages in `.venv` | Torch 2.7.1+cu118, CUDA True, AgentDojo 0.1.35, OpenAI 3.28.0 |

---

## 6. Failures and Unresolved Issues
- None. All diagnostic commands succeeded, GPU compute was verified via `nvidia-smi`, the Ollama service was responsive, and all target packages loaded cleanly.

---

## 7. Known Limitations and Risks
- **Laptop VRAM Ceiling (6 GB):** While `qwen2.5:3b` fits completely in VRAM (~2.2 GB used), larger models (e.g. 12B) trigger CPU layer offloading. For Direction B, sequential agent execution using `qwen2.5:3b` is recommended to maintain fast inference (~0.06s eval duration per query) and prevent VRAM exhaustion.
- **RAM Headroom:** Free physical RAM is ~4.8 GB. Running large background desktop applications alongside multiple heavy Python subprocesses should be minimized.

---

## 8. Status and Next Steps
- **Phase 00 Status:** **PASS (COMPLETE)**.
- **Stop Condition Met:** Pausing execution. Waiting for explicit user review and approval before proceeding to **Phase 01 — Research Question and Design**.
