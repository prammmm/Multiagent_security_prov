"""Deterministic pre-execution validation safeguards outside the LLM reasoning loop.

Enforces fail-closed validation on proposed actions prior to tool execution, preventing
direction inversions, unintended transfers, or invalid operations from mutating the environment.
"""

import re
import math
import json
from typing import Any, Dict, List, Optional, Tuple, Set

from src.pipeline.schema import ActionProposal


REFUND_RECEIVED_PATTERN = re.compile(
    r"\b(what\s+they(?:'ve|\s+have)?\s+sent(?:\s+me)?|"
    r"what\s+they\s+paid(?:\s+me)?|"
    r"what\s+they\s+transferred(?:\s+me)?|"
    r"what\s+they\s+gave(?:\s+me)?|"
    r"(?:they|counterparty|sender)\s+(?:have\s+)?sent(?:\s+me)?|"
    r"(?:they|counterparty|sender)\s+(?:have\s+)?paid(?:\s+me)?|"
    r"sent\s+me|"
    r"paid\s+me|"
    r"transferred\s+to\s+me|"
    r"received\s+from)\b",
    re.IGNORECASE,
)

USER_ACCOUNT_IDENTIFIERS: Set[str] = {"me", "user", "self", "my_account"}


def is_refund_received_request(user_prompt: str) -> bool:
    """Determine whether user prompt specifically requests refunding funds received from a counterparty."""
    if not user_prompt:
        return False
    has_refund = bool(re.search(r"\brefund\b", user_prompt, re.IGNORECASE))
    if not has_refund:
        return False
    return bool(REFUND_RECEIVED_PATTERN.search(user_prompt))


def extract_intended_counterparty(user_prompt: str) -> Optional[str]:
    """Extract the intended counterparty explicitly identified in the user prompt.
    
    Returns the normalized counterparty string if uniquely identified, or None if
    missing or ambiguous.
    """
    if not user_prompt:
        return None

    # 1. Search for IBANs
    ibans = re.findall(r"\b[A-Za-z]{2}\d{10,30}\b", user_prompt)
    unique_ibans = list(dict.fromkeys(ibans))
    if len(unique_ibans) == 1:
        return unique_ibans[0]
    elif len(unique_ibans) > 1:
        m = re.search(r"\brefund\s+([A-Za-z]{2}\d{10,30})\b", user_prompt, re.IGNORECASE)
        if m:
            return m.group(1)
        return None

    # 2. Search for emails
    emails = re.findall(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*\b", user_prompt)
    unique_emails = list(dict.fromkeys(emails))
    if len(unique_emails) == 1:
        return unique_emails[0]
    elif len(unique_emails) > 1:
        m = re.search(r"\brefund\s+([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*)\b", user_prompt, re.IGNORECASE)
        if m:
            return m.group(1)
        return None

    # 3. Check for pattern: "refund <name> for"
    m_name = re.search(r"\brefund\s+([a-zA-Z0-9_\-]+)\s+for\b", user_prompt, re.IGNORECASE)
    if m_name:
        cand = m_name.group(1).strip()
        if cand.lower() not in {"the", "my", "me", "account", "someone", "them", "him", "her"}:
            return cand

    return None


def parse_transactions_from_output(raw_output: Any) -> Tuple[List[Dict[str, Any]], bool]:
    """Parse transaction records from structured objects, dictionaries, JSON, or string representations.
    
    Returns (valid_transactions, has_malformed_records).
    Rejects malformed records lacking required fields or containing non-finite/unusable amounts.
    Never converts missing amounts to 0.0.
    """
    txs: List[Dict[str, Any]] = []
    has_malformed = False
    if raw_output is None:
        return txs, False

    # Case 1: List of objects or dicts
    if isinstance(raw_output, list):
        for item in raw_output:
            if hasattr(item, "sender") and hasattr(item, "recipient") and hasattr(item, "amount"):
                sender = str(item.sender).strip() if item.sender is not None else ""
                recip = str(item.recipient).strip() if item.recipient is not None else ""
                raw_amt = item.amount
                if not sender or not recip or raw_amt is None:
                    has_malformed = True
                    continue
                try:
                    amt = float(raw_amt)
                    if not math.isfinite(amt) or amt <= 0:
                        has_malformed = True
                        continue
                    txs.append({
                        "id": getattr(item, "id", None),
                        "sender": sender,
                        "recipient": recip,
                        "amount": amt,
                        "subject": str(getattr(item, "subject", "")),
                        "date": str(getattr(item, "date", "")),
                    })
                except (ValueError, TypeError):
                    has_malformed = True
                    continue
            elif isinstance(item, dict):
                sender = str(item.get("sender", "")).strip() if item.get("sender") is not None else ""
                recip = str(item.get("recipient", "")).strip() if item.get("recipient") is not None else ""
                raw_amt = item.get("amount")
                if not sender or not recip or raw_amt is None:
                    has_malformed = True
                    continue
                try:
                    amt = float(raw_amt)
                    if not math.isfinite(amt) or amt <= 0:
                        has_malformed = True
                        continue
                    txs.append({
                        "id": item.get("id"),
                        "sender": sender,
                        "recipient": recip,
                        "amount": amt,
                        "subject": str(item.get("subject", "")),
                        "date": str(item.get("date", "")),
                    })
                except (ValueError, TypeError):
                    has_malformed = True
                    continue
            else:
                has_malformed = True
        return txs, has_malformed

    # Case 2: String representation
    text = str(raw_output).strip()
    if not text:
        return txs, False

    # Attempt JSON parse if formatted as JSON array or object
    if (text.startswith("[") and text.endswith("]")) or (text.startswith("{") and text.endswith("}")):
        try:
            parsed_json = json.loads(text)
            if isinstance(parsed_json, list):
                return parse_transactions_from_output(parsed_json)
            elif isinstance(parsed_json, dict) and "sender" in parsed_json:
                return parse_transactions_from_output([parsed_json])
        except (json.JSONDecodeError, ValueError):
            pass

    # Extract Transaction(...) named instances
    matches = list(re.finditer(r"Transaction\s*\((.*?)\)", text, re.DOTALL))
    if not matches and "Transaction" in text:
        has_malformed = True

    for match in matches:
        block = match.group(1)
        id_m = re.search(r"\bid\s*=\s*([^\s,]+)", block)
        sender_m = re.search(r"\bsender\s*=\s*['\"]?([^,'\"]+)['\"]?", block)
        recip_m = re.search(r"\brecipient\s*=\s*['\"]?([^,'\"]+)['\"]?", block)
        amt_m = re.search(r"\bamount\s*=\s*([^\s,]+)", block)
        subj_m = re.search(r"\bsubject\s*=\s*['\"]([^'\"]*)['\"]", block)
        date_m = re.search(r"\bdate\s*=\s*['\"]([^'\"]*)['\"]", block)

        if not sender_m or not recip_m or not amt_m:
            has_malformed = True
            continue

        sender_val = sender_m.group(1).strip()
        recip_val = recip_m.group(1).strip()
        raw_amt_str = amt_m.group(1).rstrip("),")

        if not sender_val or not recip_val:
            has_malformed = True
            continue

        try:
            amt = float(raw_amt_str)
            if not math.isfinite(amt) or amt <= 0:
                has_malformed = True
                continue
            txs.append({
                "id": id_m.group(1) if id_m else None,
                "sender": sender_val,
                "recipient": recip_val,
                "amount": amt,
                "subject": subj_m.group(1) if subj_m else "",
                "date": date_m.group(1) if date_m else "",
            })
        except (ValueError, TypeError):
            has_malformed = True
            continue

    return txs, has_malformed


def extract_all_transactions(observations: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool]:
    """Extract and aggregate all transaction records from observation history.
    
    Returns (transactions, any_malformed_found).
    """
    all_txs: List[Dict[str, Any]] = []
    any_malformed = False
    if not observations:
        return all_txs, False
    for obs in observations:
        raw = obs.get("output")
        if raw is None:
            raw = obs.get("raw_output")
        if raw is not None:
            txs, malformed = parse_transactions_from_output(raw)
            all_txs.extend(txs)
            if malformed:
                any_malformed = True
    return all_txs, any_malformed


def validate_refund_direction(
    proposal: ActionProposal,
    user_prompt: str,
    observations: List[Dict[str, Any]],
    user_account_iban: Optional[str] = None,
) -> Tuple[bool, str]:
    """Deterministic, fail-closed guard for refund requests identifying money received from a counterparty.
    
    Validates:
    1. Requested counterparty independently from the user prompt (rejects recipient substitutions).
    2. Proposed amount is a finite, positive financial amount (rejects missing/invalid amounts).
    3. Transaction records are well-formed (rejects malformed records).
    4. Transaction direction: incoming must be evidenced as money sent by counterparty to user
       ('me' or user IBAN), not to a third party.
    5. Amount correspondence: proposed amount must match the verified incoming transaction,
       not an outgoing transaction.
    """
    if proposal.tool_name != "send_money":
        return True, "Tool is not send_money; refund direction guard not applicable."

    if not is_refund_received_request(user_prompt):
        return True, "User prompt is not a refund-for-received-funds request; guard not applicable."

    arguments = proposal.arguments
    if not isinstance(arguments, dict):
        return False, "Proposed arguments must be a dictionary."

    # 1. Independent Counterparty Validation
    intended_counterparty = extract_intended_counterparty(user_prompt)
    if not intended_counterparty:
        return False, (
            "Cannot unambiguously determine the intended refund counterparty from the user prompt."
        )

    recipient = str(arguments.get("recipient", "")).strip()
    if not recipient:
        return False, "Missing recipient in proposed send_money action."

    if recipient.lower() != intended_counterparty.lower():
        return False, (
            f"Recipient substitution rejected: proposed recipient '{recipient}' does not match "
            f"the counterparty explicitly authorized in the user prompt ('{intended_counterparty}')."
        )

    # 2. Proposed Amount Validation (reject missing/malformed amounts)
    proposed_amount_raw = arguments.get("amount")
    if proposed_amount_raw is None:
        return False, "Missing amount in proposed send_money action."

    try:
        proposed_amount = float(proposed_amount_raw)
    except (ValueError, TypeError):
        return False, f"Invalid amount '{proposed_amount_raw}' in proposed send_money action."

    if not math.isfinite(proposed_amount) or proposed_amount <= 0:
        return False, f"Non-finite or non-positive amount '{proposed_amount_raw}' in proposed send_money action."

    # 3. Extract Transactions and Verify Financial Records
    all_txs, has_malformed = extract_all_transactions(observations)
    if not all_txs:
        if has_malformed:
            return False, "Observed transaction records are malformed and unusable as financial evidence."
        return False, "No observed transaction records found to verify refund direction."

    recip_lower = recipient.lower()
    counterparty_txs = [
        tx for tx in all_txs
        if tx["sender"].lower() == recip_lower or tx["recipient"].lower() == recip_lower
    ]

    if not counterparty_txs:
        if has_malformed:
            return False, "Financial records involving counterparty are malformed or unusable."
        return False, f"No observed transactions found involving counterparty '{recipient}'."

    # Established representations of user's account in AgentDojo banking
    user_identifiers = set(USER_ACCOUNT_IDENTIFIERS)
    if user_account_iban:
        user_identifiers.add(user_account_iban.lower().strip())

    # 4. Strict Direction Verification
    # Incoming to user: sender is counterparty AND recipient is user's account
    incoming_to_user_txs = [
        tx for tx in counterparty_txs
        if tx["sender"].lower() == recip_lower and tx["recipient"].lower() in user_identifiers
    ]

    # Outgoing from user: sender is user's account AND recipient is counterparty
    outgoing_from_user_txs = [
        tx for tx in counterparty_txs
        if tx["recipient"].lower() == recip_lower and tx["sender"].lower() in user_identifiers
    ]

    # Counterparty transfers to third parties (not user)
    third_party_txs = [
        tx for tx in counterparty_txs
        if tx["sender"].lower() == recip_lower and tx["recipient"].lower() not in user_identifiers
    ]

    if not incoming_to_user_txs:
        if third_party_txs:
            third_parties = sorted(list({tx["recipient"] for tx in third_party_txs}))
            return False, (
                f"Missing incoming transaction evidence: counterparty '{recipient}' transferred funds "
                f"to third parties ({third_parties}), not to the user. Direction cannot be established."
            )
        return False, (
            f"Missing incoming transaction evidence: counterparty '{recipient}' "
            f"has not sent any funds to the user in observed transactions."
        )

    # 5. Ambiguity Check among incoming transactions
    incoming_amounts = {round(tx["amount"], 4) for tx in incoming_to_user_txs}
    if len(incoming_amounts) > 1:
        return False, (
            f"Ambiguous incoming transaction records: found multiple conflicting incoming amounts "
            f"({sorted(list(incoming_amounts))}) from counterparty '{recipient}' without unambiguous resolution."
        )

    expected_incoming_amount = incoming_to_user_txs[0]["amount"]

    # 6. Direction Inversion Check
    matching_outgoing = [
        tx for tx in outgoing_from_user_txs
        if math.isclose(proposed_amount, tx["amount"], rel_tol=1e-4, abs_tol=1e-4)
    ]

    if matching_outgoing and not math.isclose(proposed_amount, expected_incoming_amount, rel_tol=1e-4, abs_tol=1e-4):
        out_ids = [str(tx.get("id")) for tx in matching_outgoing if tx.get("id") is not None]
        out_str = f" (ID: {', '.join(out_ids)})" if out_ids else ""
        in_id = incoming_to_user_txs[0].get("id")
        in_str = f" from ID: {in_id}" if in_id is not None else ""
        return False, (
            f"Refund direction mismatch: proposed amount {proposed_amount} corresponds to outgoing "
            f"transaction{out_str} to '{recipient}' rather than the incoming transaction amount "
            f"({expected_incoming_amount}{in_str})."
        )

    # 7. Exact match with expected incoming amount
    if not math.isclose(proposed_amount, expected_incoming_amount, rel_tol=1e-4, abs_tol=1e-4):
        return False, (
            f"Refund amount mismatch: proposed amount {proposed_amount} does not match "
            f"observed incoming transaction amount ({expected_incoming_amount}) from counterparty '{recipient}'."
        )

    return True, f"Refund proposal matches incoming transaction evidence (amount {expected_incoming_amount})."


CALENDAR_EVENT_ID_TOOLS: Set[str] = {
    "add_calendar_event_participants",
    "reschedule_calendar_event",
    "cancel_calendar_event",
}


def parse_calendar_events_from_output(raw_output: Any) -> Tuple[List[Dict[str, Any]], bool]:
    """Parse calendar event records from structured objects, dicts, JSON, or string representations.
    
    Returns (valid_events, has_malformed_records).
    Rejects malformed records lacking required fields.
    """
    events: List[Dict[str, Any]] = []
    has_malformed = False
    if raw_output is None:
        return events, False

    # Case 1: List of objects or dicts
    if isinstance(raw_output, list):
        for item in raw_output:
            if hasattr(item, "id_") or hasattr(item, "id"):
                eid = getattr(item, "id_", None) or getattr(item, "id", None)
                title = getattr(item, "title", None)
                if not eid or str(eid).strip() == "":
                    has_malformed = True
                    continue
                events.append({
                    "id": str(eid).strip(),
                    "title": str(title).strip() if title is not None else "",
                    "start_time": str(getattr(item, "start_time", "")),
                    "description": str(getattr(item, "description", "")),
                })
            elif isinstance(item, dict):
                eid = item.get("id_") or item.get("id")
                if not eid or str(eid).strip() == "":
                    has_malformed = True
                    continue
                events.append({
                    "id": str(eid).strip(),
                    "title": str(item.get("title", "")).strip(),
                    "start_time": str(item.get("start_time", "")),
                    "description": str(item.get("description", "")),
                })
            else:
                has_malformed = True
        return events, has_malformed

    # Case 2: String representation
    text = str(raw_output).strip()
    if not text:
        return events, False

    if "No events found" in text:
        return events, False

    # Regex pattern to match CalendarEvent(...) blocks
    pattern = re.compile(r"""CalendarEvent\s*\((.*?)(?=\bCalendarEvent\s*\(|\Z)""", re.DOTALL)
    blocks = pattern.findall(text)
    if blocks:
        for block in blocks:
            id_m = re.search(r"""\b(?:['"]?id_?['"]?)\s*[=:]\s*['"]([^'"]+)['"]""", block)
            title_m = re.search(r"""\btitle\s*[=:]\s*['"]([^'"]+)['"]""", block)
            date_m = re.search(r"""start_time=datetime\.datetime\((\d{4},\s*\d{1,2},\s*\d{1,2})""", block)
            if not id_m or not id_m.group(1).strip():
                has_malformed = True
                continue
            date_str = ""
            if date_m:
                parts = [p.strip() for p in date_m.group(1).split(",")]
                if len(parts) == 3:
                    date_str = f"{int(parts[0]):04d}-{int(parts[1]):02d}-{int(parts[2]):02d}"
            events.append({
                "id": id_m.group(1).strip(),
                "title": title_m.group(1).strip() if title_m else "",
                "date": date_str,
                "raw": block,
            })
        return events, has_malformed

    # Dict or JSON matches in string
    dict_pattern = re.compile(r"""\{[^{}]*['"]id_?['"]\s*:\s*['"]([^'"]+)['"][^{}]*\}""")
    dict_matches = dict_pattern.findall(text)
    if dict_matches:
        for dm in dict_matches:
            if not dm.strip():
                has_malformed = True
                continue
            events.append({"id": dm.strip(), "title": ""})
        return events, has_malformed

    # If text refers to events but could not be parsed
    if "CalendarEvent" in text or "event" in text.lower():
        has_malformed = True

    return events, has_malformed


def validate_calendar_event_id(
    proposal: ActionProposal,
    user_prompt: str,
    observations: List[Dict[str, Any]],
) -> Tuple[bool, str]:
    """Deterministic semantic validation for actions operating on an existing calendar event.
    
    Verifies that the proposed event_id matches an authentic observed event record
    and corresponds to the relevant event specified in the user request.
    Fails closed if evidence is missing, malformed, or ambiguous.
    """
    tool_name = (proposal.tool_name or "").lower()
    if tool_name not in CALENDAR_EVENT_ID_TOOLS:
        return True, f"Tool '{proposal.tool_name}' does not operate on an existing calendar event ID."

    if not isinstance(proposal.arguments, dict) or "event_id" not in proposal.arguments:
        return False, f"Missing required 'event_id' argument in proposal for tool '{proposal.tool_name}'."

    raw_event_id = proposal.arguments.get("event_id")
    if raw_event_id is None or str(raw_event_id).strip() == "":
        return False, f"Missing or empty 'event_id' argument in proposal for tool '{proposal.tool_name}'."

    proposed_id = str(raw_event_id).strip()

    # Filter observations for calendar observations
    cal_obs = [
        obs for obs in (observations or [])
        if obs.get("tool") in ("search_calendar_events", "get_day_calendar_events")
        or "CalendarEvent" in str(obs.get("output", ""))
    ]

    if not cal_obs:
        return False, (
            f"Cannot validate calendar event ID '{proposed_id}': no calendar observations were gathered."
        )

    all_events: List[Dict[str, Any]] = []
    any_malformed = False
    for obs in cal_obs:
        evs, mal = parse_calendar_events_from_output(obs.get("output"))
        all_events.extend(evs)
        if mal:
            any_malformed = True

    if any_malformed:
        return False, (
            f"Cannot validate calendar event ID '{proposed_id}': observed calendar records contain malformed or unparseable data."
        )

    if not all_events:
        return False, (
            f"Cannot validate calendar event ID '{proposed_id}': observed calendar queries returned no events."
        )

    observed_event_map = {e["id"]: e for e in all_events if e.get("id")}
    observed_ids = set(observed_event_map.keys())

    if proposed_id not in observed_ids:
        return False, (
            f"Calendar event ID mismatch: proposed event_id '{proposed_id}' does not match any observed calendar event ID ({sorted(list(observed_ids))})."
        )

    matched_event = observed_event_map[proposed_id]
    matched_title = matched_event.get("title", "").strip().lower()

    # Extract potential event titles from user prompt (e.g. quoted phrases)
    quoted_phrases = re.findall(r"['\"]([^'\"]+)['\"]", user_prompt)
    target_titles = [
        p.strip().lower() for p in quoted_phrases
        if "@" not in p and not p.endswith((".txt", ".json", ".csv", ".pdf")) and len(p.strip()) > 2
    ]

    # If the user explicitly requested a specific title, ensure the matched event is relevant
    for target in target_titles:
        if not (target in matched_title or matched_title in target):
            return False, (
                f"Event relevance mismatch: proposed event_id '{proposed_id}' corresponds to '{matched_event.get('title', '')}', "
                f"not the requested event '{target}'."
            )

        # Check if there are other conflicting events matching the target title with a different ID
        conflicting_events = [
            e for e in all_events
            if (target in e.get("title", "").lower() or e.get("title", "").lower() in target)
            and e["id"] != proposed_id
        ]
        if conflicting_events:
            conflicting_ids = sorted(list({e["id"] for e in conflicting_events} | {proposed_id}))
            return False, (
                f"Ambiguous calendar event records: multiple observed events match the requested event '{target}' "
                f"with conflicting IDs ({conflicting_ids})."
            )

    return True, f"Proposed event_id '{proposed_id}' verified against observed calendar record '{matched_event.get('title', '')}'."


def validate_action_pre_execution(
    proposal: ActionProposal,
    user_prompt: str,
    observations: List[Dict[str, Any]],
    user_account_iban: Optional[str] = None,
) -> Tuple[bool, str]:
    """Pre-execution validation gateway running immediately before tool runtime dispatch."""
    tool = (proposal.tool_name or "").lower()
    if tool == "send_money":
        return validate_refund_direction(
            proposal=proposal,
            user_prompt=user_prompt,
            observations=observations,
            user_account_iban=user_account_iban,
        )
    if tool in CALENDAR_EVENT_ID_TOOLS:
        return validate_calendar_event_id(
            proposal=proposal,
            user_prompt=user_prompt,
            observations=observations,
        )
    return True, f"Tool '{proposal.tool_name}' is not send_money or calendar update; pre-execution validation not applicable."
