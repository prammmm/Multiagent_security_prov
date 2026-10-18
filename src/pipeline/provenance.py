"""Provenance management, cryptographic hashing, and origin-based lineage tracking across transformations."""

import re
import hashlib
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from src.pipeline.schema import (
    ProvenanceTag,
    StructuredClaim,
    HandoffPayload,
    ArgumentEvidence,
    TrustLevel,
    OriginType,
    TransformationType,
    ProvenanceMethod,
)


def compute_content_hash(content: str) -> str:
    """Compute deterministic SHA-256 digest of textual content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def extract_sensitive_entities(text: str) -> Dict[str, str]:
    """Extract potentially sensitive argument candidates (emails, IBANs, URLs, filenames) from text.
    
    Returns a dictionary mapping normalized (lowercase, punctuation-stripped) entity to its category.
    """
    entities: Dict[str, str] = {}
    if not text:
        return entities

    # 1. Email addresses
    emails = re.findall(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*\b", text)
    for email in emails:
        clean = email.rstrip(".,;:!?").strip().lower()
        if "@" in clean and len(clean) > 4:
            entities[clean] = "email"

    # 2. IBANs / Account numbers (e.g., US133000000121212121212, UK12345678901234567890)
    ibans = re.findall(r"\b[A-Za-z]{2}\d{10,30}\b", text)
    for iban in ibans:
        clean = iban.strip().lower()
        entities[clean] = "iban"

    # 3. Filenames with extensions (.txt, .json, .csv, .pdf)
    filenames = re.findall(r"\b[a-zA-Z0-9_\-]+\.(?:txt|json|csv|pdf|docx)\b", text, re.IGNORECASE)
    for fname in filenames:
        clean = fname.strip().lower()
        entities[clean] = "filename"

    # 4. URLs (http, https, and www.)
    urls = re.findall(r"(?:https?://|www\.)[^\s<>\"']+", text)
    for url in urls:
        clean = url.rstrip(".,;:!?'\")").strip().lower()
        entities[clean] = "url"

    return entities


class ProvenanceTracker:
    """Manages observation ingestion, handoff packaging, and downstream argument lineage checking.
    
    Attribution derives strictly from origin boundaries (User Prompt vs Tool Observations),
    never from benchmark-specific delimiters, keywords, or presumed text maliciousness.
    """

    def __init__(self, user_goal: str):
        self.user_goal = user_goal
        self.user_goal_hash = compute_content_hash(user_goal)
        self.user_entities = extract_sensitive_entities(user_goal)
        self.observations: List[Dict[str, Any]] = []
        self.untrusted_entities: Dict[str, str] = {}          # entity -> source_id
        self.structured_claims: List[StructuredClaim] = []     # List of extracted claims

        # Register user prompt as root trusted source
        self.user_tag = ProvenanceTag(
            source_id="user_prompt",
            origin_type=OriginType.USER_PROMPT,
            trust_level=TrustLevel.TRUSTED,
            content_hash=self.user_goal_hash,
            parent_source_ids=[],
            transformation_history=[TransformationType.IDENTITY],
            provenance_method=ProvenanceMethod.USER_SPECIFICATION,
            source_metadata={"role": "user", "length": len(user_goal)},
        )

    def register_observation(
        self,
        source_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        raw_output: str,
        origin_type: OriginType = OriginType.TOOL_OBSERVATION,
        is_trusted: bool = False,
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> ProvenanceTag:
        """Record an observation returned from a tool call at the ingestion boundary.
        
        Origin is designated as TOOL_OBSERVATION (UNTRUSTED by default).
        No delimiters or keyword heuristics are used to determine origin.
        """
        trust = TrustLevel.TRUSTED if is_trusted else TrustLevel.UNTRUSTED
        content_hash = compute_content_hash(raw_output)

        meta = source_metadata or {}
        meta.update({
            "tool_name": tool_name,
            "tool_args": tool_args,
            "output_length": len(raw_output),
        })

        tag = ProvenanceTag(
            source_id=source_id,
            origin_type=origin_type,
            trust_level=trust,
            content_hash=content_hash,
            parent_source_ids=[],
            transformation_history=[TransformationType.IDENTITY],
            provenance_method=ProvenanceMethod.EXPLICIT_SOURCE_METADATA,
            source_metadata=meta,
        )

        self.observations.append({
            "source_id": source_id,
            "tool": tool_name,
            "tool_name": tool_name,
            "args": tool_args,
            "tool_args": tool_args,
            "output": raw_output,
            "raw_output": raw_output,
            "tag": tag,
        })

        # All entities extracted from an external observation inherit UNTRUSTED origin
        extracted = extract_sensitive_entities(raw_output)
        for entity, category in extracted.items():
            # If entity was not already authorized in the root user prompt, record as untrusted observation entity
            if entity not in self.user_entities:
                self.untrusted_entities[entity] = source_id

                claim = StructuredClaim(
                    claim_id=f"claim-{uuid.uuid4().hex[:8]}",
                    field_name=category,
                    field_value=entity,
                    source_id=source_id,
                    trust_level=TrustLevel.DERIVED_TAINTED if not is_trusted else TrustLevel.TRUSTED,
                    provenance_method=ProvenanceMethod.STRUCTURED_EXTRACTION,
                )
                self.structured_claims.append(claim)

        # Extract authentic resource identifiers from observations (e.g. calendar event IDs)
        # These represent observed system resource references rather than untrusted payload entities.
        event_id_matches = re.findall(r"""\b(?:['"]?id_?['"]?)\s*[=:]\s*['"]([^'"]+)['"]""", raw_output)
        for eid in dict.fromkeys(event_id_matches):
            claim = StructuredClaim(
                claim_id=f"claim-{uuid.uuid4().hex[:8]}",
                field_name="event_id",
                field_value=eid,
                source_id=source_id,
                trust_level=TrustLevel.TRUSTED,
                parent_source_ids=[source_id],
                transformation_history=[TransformationType.EXTRACTION],
                provenance_method=ProvenanceMethod.STRUCTURED_EXTRACTION,
            )
            self.structured_claims.append(claim)

        return tag

    def register_structured_claim(
        self,
        field_name: str,
        field_value: Any,
        source_id: str,
        trust_level: TrustLevel = TrustLevel.TRUSTED,
        provenance_method: ProvenanceMethod = ProvenanceMethod.STRUCTURED_EXTRACTION,
        parent_source_ids: Optional[List[str]] = None,
        transformation_history: Optional[List[TransformationType]] = None,
        arithmetic_detail: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
    ) -> StructuredClaim:
        """Register a discrete structured claim with grounded provenance."""
        claim = StructuredClaim(
            claim_id=f"claim-{uuid.uuid4().hex[:8]}",
            field_name=field_name,
            field_value=field_value,
            source_id=source_id,
            trust_level=trust_level,
            provenance_method=provenance_method,
            parent_source_ids=parent_source_ids or ([source_id] if source_id else []),
            transformation_history=transformation_history or [TransformationType.EXTRACTION],
            arithmetic_detail=arithmetic_detail,
            confidence=confidence,
        )
        self.structured_claims.append(claim)
        return claim

    def register_derived_claim(
        self,
        field_name: str,
        field_value: Any,
        source_id: str,
        parent_source_ids: List[str],
        arithmetic_detail: Dict[str, Any],
        trust_level: TrustLevel = TrustLevel.TRUSTED,
        transformation_history: Optional[List[TransformationType]] = None,
    ) -> StructuredClaim:
        """Register an arithmetically derived claim with multi-parent observation lineage."""
        return self.register_structured_claim(
            field_name=field_name,
            field_value=field_value,
            source_id=source_id,
            trust_level=trust_level,
            provenance_method=ProvenanceMethod.ARITHMETIC_DERIVATION,
            parent_source_ids=parent_source_ids,
            transformation_history=transformation_history or [
                TransformationType.EXTRACTION,
                TransformationType.ARITHMETIC_DERIVATION,
            ],
            arithmetic_detail=arithmetic_detail,
        )

    def create_handoff(
        self,
        handoff_id: str,
        summary_text: str,
        transformation_type: TransformationType = TransformationType.SUMMARIZATION,
        previous_handoff: Optional[HandoffPayload] = None,
        source_tags: Optional[List[ProvenanceTag]] = None,
        authoritative_goal: Optional[str] = None,
        untrusted_embedded_instructions: Optional[List[str]] = None,
        relevant_facts: Optional[List[str]] = None,
        unresolved_information: Optional[List[str]] = None,
        structured_claims: Optional[List[StructuredClaim]] = None,
    ) -> HandoffPayload:
        """Construct a structured HandoffPayload packaging natural language summary with explicit lineage."""
        if previous_handoff is not None:
            base_tags = previous_handoff.provenance_tags
            active_claims = list(previous_handoff.structured_claims)
        elif source_tags is not None:
            base_tags = source_tags
            active_claims = list(self.structured_claims)
        else:
            base_tags = [obs["tag"] for obs in self.observations]
            active_claims = list(self.structured_claims)

        if structured_claims:
            for sc in structured_claims:
                if sc not in active_claims:
                    active_claims.append(sc)

        tags = []
        for orig_tag in base_tags:
            history = list(orig_tag.transformation_history)
            history.append(transformation_type)
            copied_tag = orig_tag.model_copy(update={"transformation_history": history}, deep=True)
            tags.append(copied_tag)

        # Extract entities from the summary text and check which ones derive from untrusted observations
        summary_entities = extract_sensitive_entities(summary_text)
        taint_in_summary = {}
        for entity in summary_entities:
            if entity in self.untrusted_entities:
                taint_in_summary[entity] = self.untrusted_entities[entity]
            elif previous_handoff and entity in previous_handoff.taint_entities:
                taint_in_summary[entity] = previous_handoff.taint_entities[entity]

        return HandoffPayload(
            handoff_id=handoff_id,
            sender_agent="researcher",
            receiver_agent="planner",
            transformation_type=transformation_type,
            summary_text=summary_text,
            provenance_tags=tags,
            structured_claims=active_claims,
            taint_entities=taint_in_summary,
            authoritative_goal=authoritative_goal or self.user_goal,
            untrusted_embedded_instructions=untrusted_embedded_instructions or [],
            relevant_facts=relevant_facts or [],
            unresolved_information=unresolved_information or [],
            confidence=1.0 if tags else 0.5,
        )

    def audit_argument_lineage(
        self,
        arg_name: str,
        arg_value: Any,
        handoff: Optional[HandoffPayload] = None,
        all_args: Optional[Dict[str, Any]] = None,
    ) -> ArgumentEvidence:
        """Audit the provenance of an action proposal argument against root user authority and observation lineages.
        
        Returns an explicit ArgumentEvidence record detailing trust level, origin source, method, and rationale.
        Never silently promotes unverified information to TRUSTED.
        """
        val_str = str(arg_value).strip().lower()
        val_float: Optional[float] = None
        try:
            val_float = float(arg_value)
        except (ValueError, TypeError):
            val_float = None

        sensitive_control_slots = {
            "recipient",
            "recipients",
            "to",
            "email",
            "destination_iban",
            "account_number",
            "url",
            "participants",
            "file_id",
            "event_id",
        }

        # 1. Check Root User Authority (USER_SPECIFICATION)
        # Did the user explicitly specify this value in their goal?
        for u_ent in self.user_entities:
            pattern_ent = rf"(?<!\w){re.escape(u_ent)}(?!\w)"
            if re.search(pattern_ent, val_str, re.IGNORECASE):
                return ArgumentEvidence(
                    argument_name=arg_name,
                    argument_value=arg_value,
                    trust_level=TrustLevel.TRUSTED,
                    source_id="user_prompt",
                    parent_source_ids=["user_prompt"],
                    transformation_history=[TransformationType.IDENTITY],
                    provenance_method=ProvenanceMethod.USER_SPECIFICATION,
                    rationale="Explicitly specified or authorized in root user goal.",
                )

        # Boundary-aware and numeric-token-aware match against user goal:
        # Prevents small tokens (e.g. '2') from falsely matching inside larger identifiers (e.g. 'GB29...')
        # and prevents numeric fragments from matching inside punctuation-separated numbers (e.g. '2' or '5' in '2.5', '1' in '1,000')
        if val_str:
            left_boundary = r"(?<![\w.,])" if val_str[0].isdigit() else r"(?<!\w)"
            right_boundary = r"(?![.,]\d)(?!\w)" if val_str[-1].isdigit() else r"(?!\w)"
            pattern_goal = rf"{left_boundary}{re.escape(val_str)}{right_boundary}"
            if re.search(pattern_goal, self.user_goal, re.IGNORECASE):
                return ArgumentEvidence(
                    argument_name=arg_name,
                    argument_value=arg_value,
                    trust_level=TrustLevel.TRUSTED,
                    source_id="user_prompt",
                    parent_source_ids=["user_prompt"],
                    transformation_history=[TransformationType.IDENTITY],
                    provenance_method=ProvenanceMethod.USER_SPECIFICATION,
                    rationale="Value appears verbatim in root user goal text.",
                )

        # 2. Check Structured Claims from Handoff or Tracker
        seen_claim_keys = set()
        active_claims = []
        for claim in (handoff.structured_claims if handoff else []) + list(self.structured_claims):
            key = (claim.field_name, str(claim.field_value).strip().lower(), claim.source_id)
            if key not in seen_claim_keys:
                seen_claim_keys.add(key)
                active_claims.append(claim)

        for claim in active_claims:
            # 2a. Check arithmetic derivation claims
            if claim.provenance_method == ProvenanceMethod.ARITHMETIC_DERIVATION:
                matched_arithmetic = False
                if val_float is not None:
                    try:
                        claim_flt = float(claim.field_value)
                        if abs(val_float - claim_flt) < 1e-4:
                            matched_arithmetic = True
                    except (ValueError, TypeError):
                        pass
                if not matched_arithmetic and str(claim.field_value).strip().lower() == val_str:
                    matched_arithmetic = True

                if matched_arithmetic:
                    # Enforce transaction binding if transaction ID is present
                    if all_args and "id" in all_args and claim.arithmetic_detail:
                        bound_id = claim.arithmetic_detail.get("transaction_id")
                        if bound_id is not None:
                            try:
                                if int(all_args["id"]) != int(bound_id):
                                    continue
                            except (ValueError, TypeError):
                                pass

                    parent_sources = list(claim.parent_source_ids) if claim.parent_source_ids else ([claim.source_id] if claim.source_id else [])
                    history = list(claim.transformation_history) if claim.transformation_history else [TransformationType.EXTRACTION, TransformationType.ARITHMETIC_DERIVATION]
                    detail = claim.arithmetic_detail or {}
                    op_str = detail.get("operation", "")
                    bound_id = detail.get("transaction_id")
                    tx_str = f" for transaction {bound_id}" if bound_id is not None else ""
                    srcs_str = f" from base observation '{parent_sources[0]}' and adjustment observation '{parent_sources[1]}'" if len(parent_sources) >= 2 else (f" in '{claim.source_id}'" if claim.source_id else "")
                    rationale = f"Arithmetically derived {arg_name} {arg_value}{tx_str} calculated{srcs_str} ({op_str})." if op_str else f"Arithmetically derived {arg_name} {arg_value} from verified sources."

                    return ArgumentEvidence(
                        argument_name=arg_name,
                        argument_value=arg_value,
                        trust_level=claim.trust_level,
                        source_id=claim.source_id,
                        parent_source_ids=parent_sources,
                        transformation_history=history,
                        arithmetic_detail=detail,
                        provenance_method=claim.provenance_method,
                        rationale=rationale,
                    )

            # 2b. Check standard structured claims
            claim_val = str(claim.field_value).strip().lower()
            if claim_val:
                matched_claim = False
                if claim_val == val_str:
                    matched_claim = True
                elif val_float is not None:
                    try:
                        if abs(val_float - float(claim_val)) < 1e-4:
                            matched_claim = True
                    except (ValueError, TypeError):
                        pass
                elif re.search(rf"(?<!\w){re.escape(claim_val)}(?!\w)", val_str, re.IGNORECASE):
                    matched_claim = True
                elif re.search(rf"(?<!\w){re.escape(val_str)}(?!\w)", claim_val, re.IGNORECASE):
                    matched_claim = True

                if matched_claim:
                    parent_sources = list(claim.parent_source_ids) if claim.parent_source_ids else ([claim.source_id] if claim.source_id else [])
                    history = list(claim.transformation_history) if claim.transformation_history else [TransformationType.EXTRACTION]
                    return ArgumentEvidence(
                        argument_name=arg_name,
                        argument_value=arg_value,
                        trust_level=claim.trust_level,
                        source_id=claim.source_id,
                        parent_source_ids=parent_sources,
                        transformation_history=history,
                        arithmetic_detail=claim.arithmetic_detail,
                        provenance_method=claim.provenance_method,
                        rationale=f"Derived from structured claim '{claim.field_name}' in observation '{claim.source_id}'.",
                    )

        # 2b. Direct check for authentic resource IDs observed in read-only observations
        if arg_name.lower() in ("event_id", "id") and val_str:
            for obs in self.observations:
                raw_out = str(obs.get("raw_output", ""))
                pattern_obs_id = rf"\b(?:['\"]?id_?['\"]?)\s*[=:]\s*['\"]?{re.escape(val_str)}['\"]?(?!\w)"
                if re.search(pattern_obs_id, raw_out, re.IGNORECASE):
                    obs_id = obs["source_id"]
                    return ArgumentEvidence(
                        argument_name=arg_name,
                        argument_value=arg_value,
                        trust_level=TrustLevel.TRUSTED,
                        source_id=obs_id,
                        parent_source_ids=[obs_id],
                        transformation_history=[TransformationType.EXTRACTION],
                        provenance_method=ProvenanceMethod.STRUCTURED_EXTRACTION,
                        rationale=f"Grounded identifier matching observed record in observation '{obs_id}'.",
                    )

        # 2c. Dynamic check for arithmetically derived amount from observations
        if arg_name.lower() == "amount" and val_float is not None and self.observations:
            from src.pipeline.researcher import derive_relative_transaction_adjustments
            adj_derivation = derive_relative_transaction_adjustments(self.user_goal, self.observations)
            if adj_derivation.get("status") == "RESOLVED":
                resolved_adj = adj_derivation.get("adjusted_amount")
                if resolved_adj is not None and abs(val_float - float(resolved_adj)) < 1e-4:
                    bound_id = adj_derivation.get("transaction_id")
                    id_match = True
                    if all_args and "id" in all_args and bound_id is not None:
                        try:
                            if int(all_args["id"]) != int(bound_id):
                                id_match = False
                        except (ValueError, TypeError):
                            pass

                    if id_match:
                        base_src = adj_derivation.get("base_source_id", "")
                        delta_src = adj_derivation.get("delta_source_id", "")
                        parents = [s for s in [base_src, delta_src] if s]
                        combined_src = f"{base_src}+{delta_src}" if base_src and delta_src else (base_src or delta_src or None)
                        history = [TransformationType.EXTRACTION, TransformationType.ARITHMETIC_DERIVATION]
                        detail = adj_derivation.get("arithmetic_detail", {})
                        op_str = detail.get("operation", "")
                        tx_str = f" for transaction {bound_id}" if bound_id is not None else ""
                        srcs_str = f" from base observation '{base_src}' and adjustment observation '{delta_src}'" if base_src and delta_src else ""
                        rationale = f"Arithmetically derived amount {arg_value}{tx_str} calculated{srcs_str} ({op_str})." if op_str else "Arithmetically derived amount from verified sources."
                        return ArgumentEvidence(
                            argument_name=arg_name,
                            argument_value=arg_value,
                            trust_level=TrustLevel.TRUSTED,
                            source_id=combined_src,
                            parent_source_ids=parents,
                            transformation_history=history,
                            arithmetic_detail=detail,
                            provenance_method=ProvenanceMethod.ARITHMETIC_DERIVATION,
                            rationale=rationale,
                        )

        # 3. Check Verbatim Entity Matches to Untrusted Observations
        active_taint_map = handoff.taint_entities if handoff else self.untrusted_entities
        for untrusted_ent, source_id in active_taint_map.items():
            if untrusted_ent in val_str:
                return ArgumentEvidence(
                    argument_name=arg_name,
                    argument_value=arg_value,
                    trust_level=TrustLevel.DERIVED_TAINTED,
                    source_id=source_id,
                    parent_source_ids=[source_id],
                    transformation_history=[TransformationType.EXTRACTION],
                    provenance_method=ProvenanceMethod.VERBATIM_ENTITY_MATCH,
                    rationale=f"Value contains entity derived from external observation '{source_id}'.",
                )

        for untrusted_ent, source_id in self.untrusted_entities.items():
            if untrusted_ent in val_str:
                return ArgumentEvidence(
                    argument_name=arg_name,
                    argument_value=arg_value,
                    trust_level=TrustLevel.DERIVED_TAINTED,
                    source_id=source_id,
                    parent_source_ids=[source_id],
                    transformation_history=[TransformationType.EXTRACTION],
                    provenance_method=ProvenanceMethod.VERBATIM_ENTITY_MATCH,
                    rationale=f"Value matches untrusted entity registered from observation '{source_id}'.",
                )

        # 4. Sensitive Control Slot with Unresolved Lineage
        # If the argument controls routing/destination and has no verified derivation:
        if arg_name.lower() in sensitive_control_slots and val_str:
            return ArgumentEvidence(
                argument_name=arg_name,
                argument_value=arg_value,
                trust_level=TrustLevel.UNCERTAIN,
                source_id=None,
                parent_source_ids=[],
                transformation_history=[],
                provenance_method=ProvenanceMethod.UNRESOLVED,
                rationale=f"Sensitive control argument '{arg_name}' has unresolved lineage and was not authorized by user.",
            )

        # 5. Operational / Neutral Argument with Unresolved Provenance
        return ArgumentEvidence(
            argument_name=arg_name,
            argument_value=arg_value,
            trust_level=TrustLevel.UNCERTAIN,
            source_id=None,
            parent_source_ids=[],
            transformation_history=[],
            provenance_method=ProvenanceMethod.UNRESOLVED,
            rationale="Unverified operational parameter with unresolved provenance.",
        )
