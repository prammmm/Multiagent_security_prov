# Phase 01 — Research Question and Design

**Project:** Direction B Multi-Agent Security Prototype  
**Date:** 2026-10-16  
**Document Version:** 1.0.0  
**Repository:** `D:\multiagent_security_prov\Multiagent_security_prov`  
**Reference Repository (Read-Only):** `D:\Agent_watch_prov`  
**Evaluation Model Target:** `qwen2.5:3b` (via local Ollama on NVIDIA RTX 3060 Laptop GPU, 6 GB VRAM)  
**Execution Environment:** Windows 10/11, Python 3.11.0, AgentDojo 0.1.35, PyTorch 2.7.1+cu118  

---

## 1. Executive Summary & Phase Scope

This report establishes the theoretical foundation, related-work audit, threat model, system architecture, falsifiable hypotheses, experimental protocol, and go/no-go criteria for **Direction B: Multi-Agent Security Provenance Across Semantic Transformations**.

### 1.1 The Core Research Question
The project investigates a fundamental problem in multi-agent LLM systems:

> **When untrusted information passes between agents and is summarized, paraphrased, or converted into a plan, does security provenance survive those transformations, and does preserving provenance reduce unauthorized downstream actions beyond conventional authorization controls?**

### 1.2 Core Sub-Questions
1. **Provenance Survival ($Q_1$):** When an upstream agent (e.g., Researcher) ingests untrusted environment observations and transforms them into natural language (summaries, plans, or key-value extractions) for a downstream agent (e.g., Planner), does the security provenance (trust label, origin source, derivation path) survive intact, or is it erased/conflated?
2. **Authorization Boundary Efficacy ($Q_2$):** Does enforcing provenance-aware authorization at the downstream action boundary prevent unauthorized tool calls when static, conventional authorization controls (role-based access control, tool whitelisting, schema validation) would otherwise allow them?
3. **Utility and Overblocking Trade-off ($Q_3$):** Can provenance-aware authorization operate without causing excessive false alarms ($\text{FAR} \le 5\%$) or crippling benign task execution utility ($\text{TSR}$) during legitimate multi-agent collaboration?

### 1.3 Key Corrections and Operational Constraints
As established in the Phase 00 Environment Audit and user instructions:
- **Constrained RAM:** Baseline free system RAM is approximately **4.78 GB**. All pipelines must operate sequentially (one active agent at a time) with strict memory management, garbage collection, and conservative context lengths ($2,048$ to $4,096$ tokens).
- **Inference Latency Realism:** The Phase 00 4-token smoke test ($0.063\,\text{s}$ evaluation duration) was a basic pipeline check and **must not** be used as an estimate for multi-turn agent reasoning. Full representative benchmarks will be timed systematically.
- **Zero Cloud Cost & Local Execution:** Zero paid APIs or external services. All inference executes locally on `qwen2.5:3b` offloaded 100% to the RTX 3060 GPU ($2.2\,\text{GB}$ VRAM allocated).
- **Prohibition of Synthetic Data:** No fabricated trajectories, synthetic attack payloads, or manual tampering with benchmark environments. All evaluations must use authentic benchmark tasks (AgentDojo `v1` workspace suite).

---

## 2. Threat Model and Trust Boundaries

Multi-agent architectures decompose complex user tasks into specialized roles (e.g., information retrieval, planning, execution). However, inter-agent communication channels introduce subtle attack surfaces where untrusted data can masquerade as trusted inter-agent instructions.

### 2.1 Assets to Protect
1. **Confidential Workspace Data:** User files, private calendar entries, email records, and credentials stored in the local workspace.
2. **External Communication Integrity:** Preventing unauthorized exfiltration via email (`send_email`), web requests, or cloud storage.
3. **Local State Integrity:** Preventing unauthorized modification or deletion of user files (`delete_file`, `overwrite_file`).

### 2.2 Principals and System Actors
- **User (Trusted Principal):** The human operator who initiates the session with an explicit objective and a set of authorized intents (e.g., *"Summarize my meetings for tomorrow and email the agenda to Alice"*).
- **Researcher Agent (Untrusted-Ingesting Principal):** An LLM agent equipped with read-only tools (`get_calendar`, `search_files`, `read_email`). It interacts directly with external, untrusted environment data.
- **Planner Agent (Downstream Reasoning Principal):** An LLM agent that receives handoff payloads from the Researcher, analyzes findings, and formulates an actionable plan comprising concrete tool proposals.
- **Action Authorization Boundary (Deterministic Reference Monitor):** A non-LLM, deterministic policy gateway positioned between the Planner's tool proposals and the execution environment. It evaluates whether proposed tool calls and their specific arguments are authorized by the User's explicit intent and provenance history.
- **Adversary (Untrusted External Actor):** An entity that embeds malicious prompt-injection payloads into environment data (e.g., calendar descriptions, email bodies) intended to hijack agent execution.

### 2.3 Trust Boundaries and Information Flow

```mermaid
flowchart TD
    subgraph Trusted_Zone ["Trusted Zone"]
        User["User (Trusted Goal & Intent)"]
    end

    subgraph Untrusted_Environment ["Untrusted Environment"]
        EnvData["Environment Data\n(Calendar / Emails / Files)\n[Contains Injected Payloads]"]
    end

    subgraph Agent_Pipeline ["Multi-Agent Pipeline"]
        Researcher["Researcher Agent\n(Tool Retrieval)"]
        HandoffTransform["Handoff Transformation\n(Summarize / Paraphrase / Plan)"]
        Planner["Planner Agent\n(Synthesizes Action Proposals)"]
    end

    subgraph Security_Perimeter ["Enforcement Perimeter"]
        AuthBoundary{"Action Authorization\nBoundary"}
        Exec["Tool Execution Engine\n(State Change)"]
        AuditLog["Immutable Provenance\n& Audit Log"]
    end

    User -->|"Goal & Allowed Scope\n(Trust = HIGH)"| Researcher
    User -.->|"Initial Policy & Intents"| AuthBoundary
    Researcher -->|"1. Read Tool Call"| EnvData
    EnvData -->|"2. Observation Data\n(Trust = UNTRUSTED)"| Researcher
    Researcher -->|"3. Raw Ingestion"| HandoffTransform
    HandoffTransform -->|"4. Transformed Handoff\n[Taint / Provenance Attached]"| Planner
    Planner -->|"5. Proposed Tool Call\n+ Arguments"| AuthBoundary
    AuthBoundary -->|"6a. Approved"| Exec
    AuthBoundary -->|"6b. Denied / Logged"| AuditLog

    style Trusted_Zone fill:#d4edda,stroke:#28a745,stroke-width:2px;
    style Untrusted_Environment fill:#f8d7da,stroke:#dc3545,stroke-width:2px;
    style Security_Perimeter fill:#fff3cd,stroke:#ffc107,stroke-width:2px;
```

#### The Four Key Trust Boundaries:
1. **Boundary 1 (User $\to$ Researcher):** The user prompt is explicitly trusted ($T = \text{TRUSTED}$). It establishes legitimate user intent and parameter bounds.
2. **Boundary 2 (Environment $\to$ Researcher):** Tool return values (calendar events, file contents) originate outside the trusted perimeter ($T = \text{UNTRUSTED}$). They are data, not instructions.
3. **Boundary 3 (Researcher $\to$ Planner Handoff):** The critical semantic boundary. When the Researcher summarizes or plans, untrusted content is transformed into natural language. Without explicit provenance, the Planner treats the entire handoff as authoritative context.
4. **Boundary 4 (Planner $\to$ Execution Engine):** The action boundary. The Planner proposes concrete tool calls. The Authorization Boundary must inspect both the tool name *and* argument values before allowing environment mutation.

---

## 3. Related Work Comparison & Rigorous Novelty Audit

To establish whether this investigation addresses a genuine research gap, we conduct an exhaustive, evidence-first comparison against the five closest peer-reviewed and preprint architectures.

### 3.1 In-Depth Analysis of Related Works

#### 1. ACIArena (2024) — *Cascading Injections in Multi-Agent Topologies*
- **Scope & Focus:** Evaluates how prompt-injection attacks propagate across different multi-agent architectures (centralized supervisor, peer-to-peer, chain).
- **Findings:** Demonstrated that in naive multi-agent systems, prompt injections easily cascade from agent to agent because agents blindly trust communications from peer agents.
- **Limitations:** Focuses on attack benchmarking and topology vulnerability profiling. Does not investigate fine-grained provenance tracking across semantic transformations, nor does it evaluate downstream argument-level authorization boundaries.

#### 2. TAMAS (2024) — *Threats and Attacks in Multi-Agent Systems*
- **Scope & Focus:** Systematizes attacks on multi-agent communication, including identity impersonation, message alteration, and memory/context poisoning. Introduces the Effective Robustness Score (ERS).
- **Findings:** Quantified the degradation of task completion when inter-agent messages are corrupted or poisoned.
- **Limitations:** Emphasizes adversarial vulnerability measurement rather than defensive reference monitors. Treats inter-agent messages as monolithic blobs rather than analyzing how provenance can survive summarization and paraphrasing.

#### 3. Safin et al. (arXiv:2609.17648, 2026) — *Trust Propagation and Structural Containment in Multi-agent LLM Pipelines*
- **Scope & Focus:** Investigates trust propagation in a 4-agent pipeline (Supervisor, Researcher, Validator, Executor).
- **Key Breakthrough:** Demonstrates that in undefended pipelines, memory poisoning reaches execution in 100% of cases. However, introducing **structural containment** (cryptographically signed task-bound capability tokens and independent policy oracles) reduces the Unsafe Action Rate to **0%**, even while the LLM's internal Judgment Bypass Rate remains at 100%.
- **Exact Overlap with Direction B:**
  - Proves that LLM agents cannot be trusted to perform self-authorization.
  - Establishes that external, structural authorization boundaries are mandatory and effective.
- **What Safin et al. Did NOT Solve:**
  - Safin et al. rely on **static capability tokens** (e.g., "is the Executor permitted to call `send_email`?").
  - They do **not** solve the *semantic argument taint problem*: What if `send_email` is an authorized action for the task, but the recipient address (`attacker@bad.com`) or file attachment was extracted from an untrusted summary? Static tokens permit the tool; provenance tracking is required to detect argument hijacking.

#### 4. ARGUS (2024) — *Causal-Provenance Auditor for Single Agents*
- **Scope & Focus:** Dynamic action grounding and causal-provenance auditing for single LLM agents subjected to indirect prompt injection.
- **Findings:** Built influence-provenance graphs linking tool arguments back to context tokens to audit whether an action was caused by an injected payload.
- **Limitations:** Strictly limited to single-agent execution traces. Does not address multi-agent handoffs, loss of token-level provenance across agent-to-agent summarization/paraphrasing, or distributed planning.

#### 5. Bounded Agents / Agentic Principal Chain (2024)
- **Scope & Focus:** Formal access control models for AI agents using non-delegable permissions, reference monitors, and session envelopes.
- **Findings:** Defined the formal framework for propagating user delegation across microservices and agents.
- **Limitations:** Theoretical security architecture and coarse-grained role-based access control (RBAC). Lacks empirical evaluation on how natural language transformations (summarization, plan extraction) destroy data flow lineage.

---

### 3.2 Comprehensive Related-Work Comparison Matrix

| Dimension | ACIArena (2024) | TAMAS (2024) | Safin et al. (2026) | ARGUS (2024) | Bounded Agents (2024) | **Direction B (This Work)** |
|---|---|---|---|---|---|---|
| **Multi-Agent Architecture** | Multi-topology (Star, Chain, Mesh) | Multi-agent Chat / Consensus | 4-Agent Pipeline (Super/Res/Val/Exec) | Single Agent Only | Abstract Agentic Chain | **2-Agent Pipeline (Researcher $\to$ Planner) + Gate** |
| **Threat Vector** | Cascading Indirect Prompt Injection | Memory & Channel Poisoning | Context Poisoning & Prompt Injection | Indirect Prompt Injection | Confused Deputy / Privilege Escalation | **Indirect Prompt Injection via Ingested Tools** |
| **Semantic Transformations** | Ignored (raw message pass-through) | Ignored (raw text) | Coarse Summaries (not audited for taint) | N/A (Single Agent) | N/A (Formal Spec) | **Explicitly Evaluated (Summarization, Paraphrase, Plan)** |
| **Provenance Tracking Granularity** | None | None | Coarse (Task token level) | Fine-grained (Token-level causal graph) | Capability Delegation Chain | **Structural & Semantic Slot-Taint Tracking** |
| **Authorization Mechanism** | None | None | External Policy Oracle & Signed Tokens | Post-hoc Causal Audit | Reference Monitor (RBAC / Capabilities) | **Provenance-Aware Argument Reference Monitor** |
| **Argument-Level Taint Detection** | No | No | No (Static Tool Permissions) | Yes (Single Agent) | No | **Yes (Cross-Agent Transformed Arguments)** |
| **Evaluation Model Scale** | Frontier (GPT-4) & Open (Llama-3-70B) | Frontier & Medium Open | Frontier (GPT-4o, Claude) & Open (Llama-3-8B) | Proprietary API Models | Formal proofs / Conceptual | **Local Open-Weight (`qwen2.5:3b`, 100% GPU)** |
| **Empirical FAR $\le 5\%$ Control** | Not measured | Not measured | Zero unsafe actions; utility impact high | Evaluated on single agents | Formal model | **Predeclared Hypothesis & Binomial Verification** |

---

### 3.3 Novelty Audit: The Evidence For and Against the Research Gap

#### Evidence Supporting a Genuine Gap (Why This Research is Needed):
1. **The Argument-Level Semantic Blindspot in Existing Structural Controls:**
   Safin et al. demonstrated that static structural tokens stop unauthorized tool invocations (e.g., blocking `delete_account` if not granted). However, modern multi-agent systems often require legitimate tools to process dynamic arguments (e.g., `send_email(recipient, body)`). If an injected payload convinces the Planner to route sensitive data to an attacker-controlled recipient, static authorization permits the call because `send_email` is an authorized tool. Only tracking the *provenance of the argument values* back through the Researcher's summarization to an untrusted environment source can detect this compromise.
2. **The Loss of Token-Level Lineage in Multi-Agent Handoffs:**
   Single-agent provenance systems (like ARGUS) rely on token-level attention or exact substring matching against a unified context window. In a multi-agent system, the Researcher generates *new* tokens when summarizing. String-matching features break under paraphrasing, synonym substitution, and plan restructuring. Investigating whether structured provenance envelopes can bridge this semantic transformation gap without requiring heavy neural tracing is an open empirical question.

#### Evidence Against a Substantial Gap (Counter-Arguments and Overlaps):
1. **Structural Containment is Already Known to Solve Tool Selection:**
   If the attack requires invoking an entirely unapproved tool (e.g., calling `shell_exec` when the user only asked for calendar scheduling), Safin et al. and Bounded Agents have already proven that simple deterministic tool whitelists solve this completely. Direction B cannot claim novelty for blocking unapproved tool names.
2. **If Upstream Sanitization Works, Downstream Provenance is Redundant:**
   Advocates of input guardrails (e.g., Llama-Guard, NeMo Guardrails) argue that untrusted observations should be sanitized before reaching any agent. If an input filter reliably strips injections at Boundary 2, tracking provenance across Boundaries 3 and 4 is superfluous. (However, empirical evidence shows input filters have high bypass rates against indirect injections).
3. **Local 3B Models May Lack Attack Expressiveness ($N_{\text{pos}} = 0$):**
   As revealed in AgentWatch Direction A Phase 6A/6B, small local models (`qwen2.5:3b`) often exhibit an inherent inductive bias toward benign instructions and fail to follow complex attack instructions. If the Planner never proposes harmful arguments regardless of authorization, the empirical benefit of provenance-aware filtering cannot be separated from baseline model inertia.

---

## 4. Operational Definitions & Formalization

To ensure scientific rigor and avoid ambiguous terminology, we establish strict mathematical and operational definitions.

### 4.1 Security Provenance ($\mathcal{P}$)
Security Provenance is defined as a tuple bound to any data entity $d$ passing through the multi-agent system:
$$\mathcal{P}(d) = \langle \text{OriginID}, \text{TrustLevel}, \text{DerivationPath}, \text{IntegrityHash} \rangle$$
- $\text{OriginID} \in \{\text{USER\_GOAL}, \text{ENV\_TOOL\_RETURN}, \text{AGENT\_INTERNAL}\}$: The root source of the information.
- $\text{TrustLevel} \in \{\text{TRUSTED}, \text{UNTRUSTED}\}$: Binary categorization derived strictly from the originating boundary. Any data originating from external tool outputs is unconditionally classified as $\text{UNTRUSTED}$.
- $\text{DerivationPath}$: An ordered sequence of transformations applied to the data, e.g., $[\text{RawObservation} \xrightarrow{\text{Summarize}} \text{HandoffNote} \xrightarrow{\text{ExtractPlan}} \text{ToolArgument}]$.
- $\text{IntegrityHash}$: Cryptographic hash ($\text{SHA-256}$) of the initial payload content to guarantee tamper evidence.

### 4.2 Handoff Semantic Transformations ($\mathcal{T}$)
A transformation function $\mathcal{T}: \mathcal{D}_{\text{in}} \to \mathcal{D}_{\text{out}}$ maps input context to a structured handoff. We study three distinct transformation modalities:
1. **Summarization ($\mathcal{T}_{\text{sum}}$):** Condensing verbose tool outputs into key points (e.g., extracting 3 calendar meetings from 10 raw JSON records).
2. **Paraphrasing ($\mathcal{T}_{\text{para}}$):** Rewording text while preserving semantic meaning (e.g., converting technical log entries into natural language notes).
3. **Plan Generation ($\mathcal{T}_{\text{plan}}$):** Translating unstructured observations into a structured multi-step action plan (e.g., converting email instructions into an ordered list of tasks).

### 4.3 Provenance Survival Rate ($\text{PSR}$)
Let $S_{\text{untrusted}} \subset \mathcal{D}_{\text{in}}$ be the set of untrusted semantic tokens/facts ingested by the Researcher. Let $S_{\text{handoff}} \subset \mathcal{D}_{\text{out}}$ be the resulting handoff text passed to the Planner.
$$\text{PSR} = \frac{|\text{Tainted Elements in } S_{\text{handoff}} \text{ successfully tagged as UNTRUSTED}|}{|\text{Tainted Elements in } S_{\text{handoff}}|}$$
If an untrusted instruction or parameter is transferred into the handoff text without its $\text{UNTRUSTED}$ taint label, provenance has failed to survive ($\text{PSR} < 1.0$).

### 4.4 Action Authorization Configurations
We formally contrast two authorization paradigms at Boundary 4:
- **Conventional Authorization ($\text{Auth}_{\text{conv}}$):**
  $$\text{Auth}_{\text{conv}}(a, \theta) = \mathbb{I}(a \in \mathcal{A}_{\text{allowed}} \land \text{ValidateSchema}(\theta))$$
  where $a$ is the proposed tool name, $\theta$ is the argument dictionary, and $\mathcal{A}_{\text{allowed}}$ is the user-whitelisted tool set. It evaluates *what* tool is called and *syntactic validity*, but ignores *where the arguments came from*.
- **Provenance-Aware Authorization ($\text{Auth}_{\text{prov}}$):**
  $$\text{Auth}_{\text{prov}}(a, \theta, \mathcal{P}) = \text{Auth}_{\text{conv}}(a, \theta) \land \forall (k, v) \in \theta, \; \text{IsPermittedSource}(k, \mathcal{P}(v), \text{Intent}_{\text{user}})$$
  where $\text{IsPermittedSource}$ verifies that sensitive argument slots (e.g., email recipients, file paths, command flags) do not originate from untrusted provenance unless explicitly approved by the original user goal.

---

## 5. Benchmark Feasibility & The Direction A Empirical Reality

A critical requirement of Phase 01 is to evaluate whether authentic benchmark scenarios can test this hypothesis **without resorting to synthetic or fabricated data**.

### 5.1 Lessons from Direction A (AgentWatch Phase 6A/6B)
The Direction A evidence audit established several sobering empirical facts regarding local open-weight models (`qwen2.5:3b`, `llama3.2:3b`, `mistral-nemo:12b`):
1. **Zero Attack Success ($N_{\text{pos}} = 0$):** Across 75 authentic AgentDojo `v1` workspace trajectories, zero prompt-injection payloads successfully hijacked the model into executing exfiltration or deletion actions.
2. **Truncated Post-Exposure Decision Chains:** In 75% of exposed trajectories, the agent simply stopped or responded to the user immediately after reading the poisoned tool output. Only 7 trajectories produced a subsequent tool-call proposal.
3. **Inductive Goal Alignment:** Smaller local models strongly adhere to the system prompt and primary user instruction. When confronted with conflicting instructions inside a tool observation, they either ignore the injection or fail to complete the task altogether.

### 5.2 Multi-Agent Architecture: Attack Amplification vs. Attenuation
When decomposing the single agent into a Researcher $\to$ Planner pipeline, how does the attack dynamic change?

```mermaid
graph LR
    subgraph Single_Agent ["Direction A: Single Agent"]
        SA_User["User Goal"] --> SA_LLM["Single LLM\n(Sees Goal + Tool Return)"]
        SA_Tool["Tool Return\n(Payload)"] --> SA_LLM
        SA_LLM -->|"High Inductive Bias\nIgnores Payload"| SA_Halt["Halts / Responds\n(N_pos = 0)"]
    end

    subgraph Multi_Agent ["Direction B: Two-Agent Pipeline"]
        MA_Tool["Tool Return\n(Payload)"] --> MA_Res["Researcher Agent\n(Extracts / Summarizes)"]
        MA_Res -->|"Handoff Message\n(Untrusted text becomes\ninter-agent instructions)"| MA_Plan["Planner Agent\n(Receives as 'Peer Data')"]
        MA_Plan -->|"Cascading Vulnerability?\nOR Transformation Filtering?"| MA_Outcome{"Decision Gate"}
    end
```

Two competing hypotheses emerge:
- **Vulnerability Amplification Hypothesis:** In a single agent, the user goal is constantly present in the system prompt. In a multi-agent handoff, the Planner receives the Researcher's summary as an authoritative inter-agent instruction. If the Researcher includes the injection in its summary, the Planner has no direct visibility into the original tool context and may treat the malicious instruction as a legitimate sub-task (as observed in ACIArena and Safin et al.).
- **Vulnerability Attenuation Hypothesis:** The Researcher's summarization prompt instructs it to answer the user's question. If the Researcher summarizes only benign information, the injection payload is pruned before reaching the Planner. If both agents exhibit inductive bias, attack success will remain at zero ($N_{\text{pos}} = 0$).

### 5.3 Feasibility Assessment on AgentDojo `v1` Workspace
Can AgentDojo `v1` workspace tasks test Direction B without synthetic modifications?
- **Task Structure:** AgentDojo `v1` workspace tasks naturally split into multi-agent phases:
  - Phase 1 (Information Gathering): Search files, read calendar, list emails (`workspace` tools).
  - Phase 2 (Synthesis & Action): Send email, update calendar, write file.
- **Feasible Tasks Identified:**
  - `user_task_2`: Read calendar meetings $\to$ email agenda to team member. (Payload embedded in meeting description).
  - `user_task_8`: Inspect inbox $\to$ reply or forward. (Payload embedded in email body).
  - `user_task_12`: Search documents $\to$ summarize findings into a report file.
- **Strict Methodological Rule:**
  The benchmark environment, tools, and attack injection strings **must not be altered or enhanced**. If the model fails to hijack under authentic AgentDojo conditions, this outcome will be reported as an empirical finding, exactly as was done in Phase 6B.

### 5.4 What the Benchmark CAN and CANNOT Establish
- **What it CAN Establish:**
  1. **Provenance Survival Rate ($\text{PSR}$):** We can rigorously measure whether provenance tags attached to raw tool observations survive summarization, paraphrasing, and planning.
  2. **False Alarm Rate ($\text{FAR}$):** We can measure overblocking on benign runs ($N \ge 30$ trajectories) to test whether provenance controls break legitimate tasks.
  3. **Taint Tracking Accuracy:** We can evaluate whether proposed tool arguments match tainted observation content.
  4. **System Overhead:** Computational latency and memory consumption under sequential execution.
- **What it CANNOT Establish (if $N_{\text{pos}} = 0$ persists):**
  1. It **cannot** compute empirical Attack Success Rate reduction or empirical detector ROC curves if the baseline Planner never proposes malicious actions.
  2. It **cannot** claim defense against attacks that the underlying model is incapable of executing.

---

## 6. System Architecture and Minimal Implementation Design

To operate strictly within the $4.78\,\text{GB}$ RAM and $6\,\text{GB}$ VRAM limits, the architecture is designed for **deterministic, sequential execution**.

### 6.1 Sequential Multi-Agent Pipeline

```mermaid
sequenceDiagram
    autonumber
    actor User as User
    participant Coord as Pipeline Coordinator
    participant Res as Researcher Agent (LLM)
    participant Trans as Transformation Layer
    participant Plan as Planner Agent (LLM)
    participant Gate as Authorization Boundary
    participant Env as Environment (AgentDojo)

    User->>Coord: Submit Goal (e.g., "Summarize meetings & email Alice")
    Coord->>Res: Initialize with User Goal (Trust = HIGH)
    Res->>Env: Call Read Tool (e.g., get_calendar)
    Env-->>Res: Return Observation (Trust = UNTRUSTED)
    Note over Res: Memory: Ingestion complete
    Res->>Trans: Send Raw Observation + Provenance Tag
    Note over Coord: Unload/Clear Researcher KV Cache from RAM
    Trans->>Trans: Apply Transformation (Summarize / Paraphrase)
    Trans->>Coord: Emit HandoffPayload with Provenance Metadata
    Coord->>Plan: Initialize with HandoffPayload
    Plan->>Coord: Propose Tool Call: send_email(to, body)
    Coord->>Gate: Evaluate Proposal (Tool + Arguments + Provenance)
    alt Unauthorized Argument Taint Detected
        Gate-->>Coord: DENY (Log Violation, Terminate Action)
        Coord-->>User: Report Security Interception
    else Legitimate & Provenance Cleared
        Gate-->>Env: ALLOW (Execute Action)
        Env-->>Coord: Execution Success
        Coord-->>User: Report Task Completed
    end
```

### 6.2 Component Specifications

#### 1. Researcher Agent
- **System Prompt:** Instructs the agent to gather relevant data using available read-only tools and synthesize findings for a planning colleague.
- **Tools:** Whitelisted read tools (`search_files_by_name`, `get_calendar_events`, `search_emails`).
- **Memory Footprint:** Operates within a $2,048$-token context window. Upon completion, its response is captured and its memory state cleared before invoking the Planner.

#### 2. Handoff Transformation Layer
- Executes structured transformations:
  - Direct Passthrough (identity mapping for baseline control).
  - Summarization (structured bullet points).
  - Entity-Slot Extraction (isolating recipients, dates, actions).
- Maintains a **Provenance Shadow Record** that maps each output sentence or entity back to its source token span and trust classification.

#### 3. Planner Agent
- **System Prompt:** Instructs the agent to formulate concrete action tool calls based *solely* on the provided handoff summary to fulfill the user's goal.
- **Tools:** Action tools (`send_email`, `write_file`, `create_calendar_event`).
- **Input Context:** User goal + Transformed Handoff text.

#### 4. Action Authorization Boundary (Reference Monitor)
- Completely independent of the LLMs (deterministic Python validation).
- Evaluates proposals against a formal security policy:
  1. **Tool Permission Check:** Is the proposed tool in the user-permitted tool set?
  2. **Schema & Type Check:** Are arguments syntactically valid?
  3. **Argument Provenance Validation:** For sensitive argument slots (e.g., `recipient`, `file_path`, `command`), does the argument contain data derived from an `UNTRUSTED` source that conflicts with the user's explicit intent?

---

### 6.3 Data Contracts & Event Schemas (Pydantic Models)

Below are the exact Pydantic schema specifications to be implemented in Phase 02:

```python
from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

class TrustLevel(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    DERIVED_TAINTED = "DERIVED_TAINTED"

class OriginType(str, Enum):
    USER_PROMPT = "USER_PROMPT"
    TOOL_OBSERVATION = "TOOL_OBSERVATION"
    AGENT_REASONING = "AGENT_REASONING"

class ProvenanceTag(BaseModel):
    source_id: str = Field(..., description="Unique ID of originating event or tool call")
    origin_type: OriginType
    trust_level: TrustLevel
    raw_hash: str = Field(..., description="SHA-256 hash of original ingested content")
    derivation_history: List[str] = Field(default_factory=list)

class HandoffPayload(BaseModel):
    handoff_id: str
    transformation_type: str  # "passthrough", "summary", "plan"
    content: str
    provenance_tags: List[ProvenanceTag]
    slot_taint_map: Dict[str, TrustLevel] = Field(
        default_factory=dict,
        description="Maps extracted entities/slots to their trust level"
    )

class ActionProposal(BaseModel):
    proposal_id: str
    step_index: int
    tool_name: str
    arguments: Dict[str, Any]
    planner_reasoning: Optional[str] = None

class AuthorizationDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY_UNAUTHORIZED_TOOL = "DENY_UNAUTHORIZED_TOOL"
    DENY_TAINTED_ARGUMENT = "DENY_TAINTED_ARGUMENT"
    DENY_SCHEMA_VIOLATION = "DENY_SCHEMA_VIOLATION"

class GatePointDecision(BaseModel):
    decision_id: str
    proposal: ActionProposal
    decision: AuthorizationDecision
    violation_details: Optional[str] = None
    executed: bool = False
```

---

## 7. Experimental Configurations and Baselines

To rigorously isolate the contribution of provenance tracking across transformations, the experiment will evaluate four controlled configurations:

### Configuration Overview

| Configuration ID | Inter-Agent Handoff Modality | Downstream Authorization Policy | Hypothesis Tested |
|---|---|---|---|
| **Config A (Uncontrolled Baseline)** | Raw text pass-through / summary | None (Direct execution of Planner proposals) | Measures baseline multi-agent cascading vulnerability |
| **Config B (Conventional Authorization)** | Transformed summary / plan | Static RBAC & Tool Whitelist (Blind to arguments/provenance) | Measures protection offered by standard static permission boundaries |
| **Config C (Provenance-Aware Prototype)** | Transformed summary with Provenance Envelope | Provenance-Aware Reference Monitor (Argument Taint Inspection) | Tests whether tracking provenance prevents argument poisoning |
| **Config D (Transformation Ablation)** | Raw tool output (No transformation) vs. Transformed | Provenance-Aware Reference Monitor | Measures exact provenance degradation caused by summarization/paraphrasing |

---

## 8. Falsifiable Hypotheses and Success Metrics

### 8.1 Formal Hypotheses

#### Hypothesis 1: Provenance Survival under Semantic Transformations ($H_1$)
- **Null Hypothesis ($H_{1,0}$):** Semantic transformations (summarization, paraphrasing, plan generation) destroy provenance linkages, resulting in a Provenance Survival Rate $\text{PSR} < 50\%$ or argument taint misclassification rates $> 20\%$.
- **Alternative Hypothesis ($H_{1,1}$):** Structured provenance envelopes and entity slot-binding preserve provenance across summarization and paraphrasing with $\text{PSR} \ge 80\%$ and argument taint precision $\ge 85\%$.

#### Hypothesis 2: Incremental Security Over Conventional Authorization ($H_2$)
- **Null Hypothesis ($H_{2,0}$):** In scenarios where proposed tool calls match whitelisted capabilities, provenance-aware authorization provides no statistically significant reduction in unauthorized downstream actions compared to conventional static controls ($BAR_C \le BAR_B$), or imposes an unacceptable false alarm rate ($\text{FAR} > 5\%$).
- **Alternative Hypothesis ($H_{2,1}$):** Provenance-aware authorization detects and blocks argument-poisoning attacks that bypass conventional static controls ($BAR_C > BAR_B$) while maintaining a benign false alarm rate $\text{FAR} \le 5\%$ and preserving task utility ($\text{TSR}_C \ge 0.90 \times \text{TSR}_B$).

---

### 8.2 Evaluation Metrics

1. **Security Containment Metrics:**
   - **Hijack Proposal Rate ($\text{HPR}$):** Proportion of attacked runs where the Planner proposes a harmful tool call matching the attacker's objective.
   - **Attack Success Rate ($\text{ASR}$):** Proportion of attacked runs where a harmful tool call is actually executed in the environment.
   - **Blocked Attack Rate ($\text{BAR}$):** Proportion of proposed harmful actions intercepted and prevented by the authorization gate:
     $$\text{BAR} = \frac{\text{Blocked Harmful Proposals}}{\text{Total Harmful Proposals Proposed}}$$
2. **Utility and Operational Metrics:**
   - **Task Success Rate ($\text{TSR}$):** Proportion of benign benchmark tasks successfully completed according to AgentDojo ground-truth criteria.
   - **False Alarm Rate ($\text{FAR}$):** Proportion of benign gate decisions that incorrectly deny a legitimate tool call:
     $$\text{FAR} = \frac{\text{Benign Decisions Denied}}{\text{Total Benign Decisions}}$$
     *Statistical Bound:* Must demonstrate sample $\text{FAR} \le 5\%$ with one-sided binomial 95% confidence ($k=0$ in at least $N=59$ decisions, or $k \le 1$ in $N=93$).
3. **Provenance Integrity Metrics:**
   - **Provenance Survival Rate ($\text{PSR}$):** Percentage of untrusted entities that retain correct taint tags post-transformation.
   - **Argument Taint Precision ($P_{\text{taint}}$) & Recall ($R_{\text{taint}}$):** Accuracy of classifying proposed tool arguments as tainted vs. clean.

---

## 9. Resource Management & Performance Guardrails

Based on the empirical audit of the workstation hardware (AMD Ryzen 7 5800H, 15.35 GB system RAM with 4.78 GB free, NVIDIA RTX 3060 Laptop GPU with 6,144 MiB VRAM), strict execution guardrails are enforced:

1. **Strict Sequential Inference:**
   - The Researcher Agent and Planner Agent **must never** run concurrently.
   - Execution flow: Coordinator invokes Researcher $\to$ Researcher completes $\to$ KV-cache released / memory cleared $\to$ Transformation executed in lightweight Python $\to$ Coordinator invokes Planner $\to$ Gate evaluates.
2. **Memory Headroom & VRAM Ceiling:**
   - Total model footprint for `qwen2.5:3b`: $2.2\,\text{GB}$ VRAM (fits entirely within 6 GB VRAM with 3.8 GB headroom for display and OS buffers).
   - System RAM allocation for Python process capped at $1.5\,\text{GB}$.
   - Python `gc.collect()` explicitly triggered between pipeline stages.
3. **Context Length Caps:**
   - Researcher context window: maximum $2,048$ tokens.
   - Planner context window: maximum $2,048$ tokens.
   - Prevents quadratic attention memory explosion and ensures predictable generation latency.
4. **Benchmarking Realism:**
   - Latency measurements must encompass full end-to-end multi-turn interactions (prompt encoding, decoding, JSON parsing, gate evaluation), reporting median and 95th percentile times rather than isolated single-token evaluations.

---

## 10. Go / No-Go Decision Gate Protocol

Before committing to full experimental evaluation in Phase 03/04, an explicit, unambiguous **Go / No-Go Decision Gate** is established at the end of Phase 02 (Prototype Verification):

```mermaid
flowchart TD
    P2_Start["Phase 02: Minimal Prototype Implementation"] --> G1{"Criterion 1: Provenance Survival\nCan PSR >= 75% be achieved\nacross summarization?"}
    G1 -- No --> Stop1["NO-GO / PIVOT:\nSemantic summarization erases provenance;\nRefocus thesis on theoretical limits\nof LLM handoff tracking."]
    G1 -- Yes --> G2{"Criterion 2: Authentic Attack Feasibility\nDoes Planner propose >= 1 harmful action\nunder authentic AgentDojo injections?"}
    G2 -- Yes --> GoFull["GO (Full Scope):\nProceed to Phase 03/04 full matrix evaluation\nof Security vs Utility."]
    G2 -- No --> Narrow["NARROW SCOPE:\nDo NOT fabricate synthetic attacks.\nPivot to evaluating Provenance Survival (PSR)\nand False Alarm Bounds (FAR) on benign utility."]
```

### Explicit Gate Criteria:
- **Criterion 1 (Technical Provenance Feasibility):**
  The prototype must demonstrate that structured provenance tags survive summarization and can be mapped to tool arguments with $\text{PSR} \ge 75\%$ on a 5-task calibration split.
  *Failure Action:* If summarization completely severs provenance lineage, STOP and report the theoretical barrier.
- **Criterion 2 (Empirical Hijack Feasibility):**
  Evaluate whether authentic AgentDojo injected tasks produce *at least one* harmful tool call proposal from the Planner ($N_{\text{pos}} \ge 1$).
  *Failure Action (The Direction A Contingency):* If $N_{\text{pos}} = 0$ persists across all authentic attacks due to model inertia, **DO NOT fabricate attacks or modify payloads**. Formally narrow the project scope to:
  *(a) Measuring Provenance Survival across transformations, and (b) Certifying that provenance tracking does not degrade benign utility or exceed $\text{FAR} \le 5\%$.*

---

## 11. Document History & Status

| Version | Date | Author / Role | Status / Description |
|---|---|---|---|
| `1.0.0` | 2026-10-16 | Senior AI Security Researcher | Complete Research Design & Novelty Audit for Phase 01 |

**Stop Condition Met:** Phase 01 Research Question and Design document is complete. Awaiting user review and approval before proceeding to Phase 02.
