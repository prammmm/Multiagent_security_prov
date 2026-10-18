"""Data contracts, event models, and trace schemas for Direction B multi-agent security pipeline."""

from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class TrustLevel(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    DERIVED_TAINTED = "DERIVED_TAINTED"
    UNCERTAIN = "UNCERTAIN"


class OriginType(str, Enum):
    USER_PROMPT = "USER_PROMPT"
    TOOL_OBSERVATION = "TOOL_OBSERVATION"
    AGENT_INTERNAL = "AGENT_INTERNAL"
    HANDOFF_DERIVED = "HANDOFF_DERIVED"


class TransformationType(str, Enum):
    IDENTITY = "IDENTITY"
    EXTRACTION = "EXTRACTION"
    SUMMARIZATION = "SUMMARIZATION"
    PARAPHRASE = "PARAPHRASE"
    PLAN_SYNTHESIS = "PLAN_SYNTHESIS"
    ARITHMETIC_DERIVATION = "ARITHMETIC_DERIVATION"


class EvaluationMode(str, Enum):
    BASELINE = "BASELINE"                      # No authorization gate (raw pass-through)
    CONVENTIONAL = "CONVENTIONAL"              # Static RBAC / Tool whitelist only
    PROVENANCE_AWARE = "PROVENANCE_AWARE"      # Tool whitelist + argument provenance taint gating


class GateDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY_UNAUTHORIZED_TOOL = "DENY_UNAUTHORIZED_TOOL"
    DENY_TAINTED_ARGUMENT = "DENY_TAINTED_ARGUMENT"
    DENY_SCHEMA_VIOLATION = "DENY_SCHEMA_VIOLATION"
    DENY_POLICY_VIOLATION = "DENY_POLICY_VIOLATION"


class ProvenanceMethod(str, Enum):
    """How the attribution of an information item or argument was established."""
    EXPLICIT_SOURCE_METADATA = "EXPLICIT_SOURCE_METADATA"  # Origin assigned at tool ingress
    USER_SPECIFICATION = "USER_SPECIFICATION"              # Explicitly specified in root user prompt
    STRUCTURED_EXTRACTION = "STRUCTURED_EXTRACTION"        # Extracted as structured claim from source
    VERBATIM_ENTITY_MATCH = "VERBATIM_ENTITY_MATCH"        # Matched entity string to source
    ARITHMETIC_DERIVATION = "ARITHMETIC_DERIVATION"        # Extracted and mathematically calculated from supporting sources
    UNRESOLVED = "UNRESOLVED"                              # Unresolved / unknown derivation


class ProvenanceTag(BaseModel):
    """Immutable provenance envelope attached to ingested observations and handoff items."""
    source_id: str = Field(..., description="Unique identifier for the source observation or prompt")
    origin_type: OriginType = Field(..., description="Root origin category")
    trust_level: TrustLevel = Field(..., description="Trust classification at source boundary")
    content_hash: str = Field(..., description="SHA-256 digest of raw ingested content")
    timestamp_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    parent_source_ids: List[str] = Field(default_factory=list, description="IDs of ancestor sources")
    transformation_history: List[TransformationType] = Field(default_factory=list)
    provenance_method: ProvenanceMethod = Field(
        default=ProvenanceMethod.EXPLICIT_SOURCE_METADATA,
        description="Method by which this tag was established"
    )
    source_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Source details: tool name, arguments, channels"
    )


class StructuredClaim(BaseModel):
    """Discrete key-value claim or entity assertion extracted from an observation."""
    claim_id: str
    field_name: str
    field_value: Any
    source_id: str
    trust_level: TrustLevel
    provenance_method: ProvenanceMethod = ProvenanceMethod.STRUCTURED_EXTRACTION
    confidence: float = 1.0
    parent_source_ids: List[str] = Field(default_factory=list, description="IDs of ancestor sources supporting this claim")
    transformation_history: List[TransformationType] = Field(default_factory=list, description="Transformations applied to derive this claim")
    arithmetic_detail: Optional[Dict[str, Any]] = Field(default=None, description="Details of calculation if derived")


class HandoffPayload(BaseModel):
    """Structured inter-agent message carrying natural-language context and explicit lineage."""
    handoff_id: str
    sender_agent: str
    receiver_agent: str
    transformation_type: TransformationType
    summary_text: str
    provenance_tags: List[ProvenanceTag]
    structured_claims: List[StructuredClaim] = Field(
        default_factory=list,
        description="Discrete claims extracted with verified source bindings"
    )
    taint_entities: Dict[str, str] = Field(
        default_factory=dict,
        description="Key-value mapping of sensitive strings/entities extracted from untrusted data (e.g. IBAN, recipient email, URLs)"
    )
    authoritative_goal: Optional[str] = Field(
        default=None,
        description="The root authoritative user request"
    )
    untrusted_embedded_instructions: List[str] = Field(
        default_factory=list,
        description="Directives or instructions found within external observations, labeled as untrusted third-party claims"
    )
    relevant_facts: List[str] = Field(
        default_factory=list,
        description="Verified facts gathered from the environment relevant to the user's task"
    )
    unresolved_information: List[str] = Field(
        default_factory=list,
        description="Parameters or information still needed to fulfill the authoritative task"
    )
    confidence: float = Field(default=1.0, description="Confidence in lineage attribution (0.0 to 1.0)")


class ArgumentEvidence(BaseModel):
    """Detailed attribution evidence supporting a proposed tool argument."""
    argument_name: str
    argument_value: Any
    trust_level: TrustLevel
    source_id: Optional[str] = None
    parent_source_ids: List[str] = Field(default_factory=list, description="IDs of ancestor sources supporting a derived argument")
    transformation_history: List[TransformationType] = Field(default_factory=list, description="Sequence of transformations producing this argument")
    arithmetic_detail: Optional[Dict[str, Any]] = Field(default=None, description="Details of calculation if derived")
    provenance_method: ProvenanceMethod = ProvenanceMethod.UNRESOLVED
    rationale: str = ""


class ActionProposal(BaseModel):
    """Tool-call proposal emitted by the Planner agent prior to authorization."""
    proposal_id: str
    step_index: int
    tool_name: str
    arguments: Dict[str, Any]
    planner_reasoning: Optional[str] = None
    argument_provenance: Dict[str, TrustLevel] = Field(
        default_factory=dict,
        description="Per-argument taint assessment derived from handoff provenance"
    )
    argument_evidence: Dict[str, ArgumentEvidence] = Field(
        default_factory=dict,
        description="Structured attribution evidence for each argument"
    )
    taint_matches: Dict[str, str] = Field(
        default_factory=dict,
        description="Per-argument matched untrusted entity source (if tainted)"
    )


class AuthorizationResult(BaseModel):
    """Audit record emitted by the Deterministic Authorization Boundary."""
    decision_id: str
    policy_version: str = "v2.0.0"
    mode: EvaluationMode
    decision: GateDecision
    reason: str
    evaluated_tool: str
    evaluated_arguments: Dict[str, Any]
    blocked_arguments: List[str] = Field(default_factory=list)
    gate_authorized: bool = Field(default=False, description="Whether the gate permits execution")
    executed: bool = Field(default=False, description="Whether the proposed action was actually dispatched to the tool runtime")
    timestamp_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ModelRequestTelemetry(BaseModel):
    """Telemetry capturing exact configuration and prompt metadata for a single model call."""
    agent_role: str
    request_stage: str
    model_name: str
    decoding_options: Dict[str, Any] = Field(default_factory=dict)
    prompt_hash: str
    prompt_char_length: int
    output_char_length: int
    wall_clock_seconds: Optional[float] = None


class TraceRecord(BaseModel):
    """Complete machine-readable audit trace for an experimental execution."""
    schema_version: str = Field(default="v2.0.0", description="Trace schema version")
    run_id: str
    benchmark_name: str = "agentdojo"
    benchmark_version: str = "v1"
    suite_name: str
    user_task_id: str
    injection_task_id: Optional[str] = None
    attack_name: Optional[str] = None
    model_name: str
    condition: EvaluationMode
    start_time_utc: str
    end_time_utc: Optional[str] = None
    user_prompt: str
    injection_payloads: Dict[str, str] = Field(default_factory=dict)
    researcher_observations: List[Dict[str, Any]] = Field(default_factory=list)
    handoff: Optional[HandoffPayload] = None
    proposals: List[ActionProposal] = Field(default_factory=list)
    gate_decisions: List[AuthorizationResult] = Field(default_factory=list)
    executed_actions: List[Dict[str, Any]] = Field(default_factory=list)

    # Disambiguated lifecycle fields
    gate_authorized: bool = Field(default=False, description="Whether the authorization boundary permitted the action")
    execution_attempted: bool = Field(default=False, description="Whether a tool invocation was dispatched")
    execution_completed: bool = Field(default=False, description="Whether the tool invocation returned successfully")
    environment_mutated: bool = Field(default=False, description="Whether a state-changing tool call was committed")

    utility_success: Optional[bool] = None
    security_breach: Optional[bool] = None
    telemetry: List[ModelRequestTelemetry] = Field(default_factory=list)
    system_metrics: Dict[str, Any] = Field(default_factory=dict)
    tool_relevance_rationales: Dict[str, str] = Field(
        default_factory=dict,
        description="Task-relevance rationales for available tools evaluated by researcher"
    )
    errors: List[str] = Field(default_factory=list)
    pipeline_version: Optional[str] = Field(default="R16.2", description="Pipeline revision identifier, e.g. R16.2, R16.3, or R16.4")
    researcher_strategy: Optional[str] = Field(default="stateless_v1", description="Researcher observation strategy (stateless_v1, observation_aware_v2, secure_observation_v3)")
