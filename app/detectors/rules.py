"""
rules.py
Evaluate every rule in the two detectors independently, so each one can be
measured on its own and sorted into:

  blocking — high validation precision; blocks a prompt by itself
  signal   — can't block alone; only escalates the prompt to the LLM judge

A "rule" is one named regex family (e.g. jb_regex:instruction_override) or one
fuzzy heuristic (e.g. jb_fuzzy:social_engineering). Matching uses exactly the
same patterns, normalisation and flags as the detectors themselves.
"""

import re
from typing import Dict, List, Optional

from app.detectors import jailbreak_detector as jb
from app.detectors import prompt_injection_detector as pi

_JB_FLAGS = re.IGNORECASE | re.DOTALL
_PI_FLAGS = re.IGNORECASE | re.DOTALL | re.MULTILINE


def _regex_hits(rules, text: str, flags: int, prefix: str) -> List[str]:
    hits = []
    for rule in rules:
        if any(re.search(p, text, flags) for p in rule["patterns"]):
            hits.append(f"{prefix}:{rule['name']}")
    return hits


def rule_hits(prompt: str, conversation_history: Optional[list] = None) -> List[str]:
    """All rules that fire on this prompt, in a stable order."""
    normalized = prompt.lower().strip()
    hits = _regex_hits(jb.REGEX_RULES, normalized, _JB_FLAGS, "jb_regex")
    hits += [f"jb_fuzzy:{r}" for r in jb.fuzzy_analyze(prompt, conversation_history)[1]]
    hits += _regex_hits(pi.REGEX_RULES, normalized, _PI_FLAGS, "pi_regex")
    hits += [f"pi_fuzzy:{r}" for r in pi.fuzzy_analyze(prompt)[1]]
    return hits


def all_rule_names() -> List[str]:
    """Every rule that rule_hits() can return (fuzzy names listed by hand from the detectors)."""
    names = [f"jb_regex:{r['name']}" for r in jb.REGEX_RULES]
    names += [f"jb_fuzzy:{n}" for n in (
        "fictional_framing_bypass", "gradual_escalation", "social_engineering",
        "leet_encoding_detected", "base64_encoded_attack", "unicode_manipulation",
        "unicode_suspicious", "extreme_length_dos", "excessive_length",
        "low_entropy_token_stuffing", "multi_persona_injection", "multi_turn_escalation")]
    names += [f"pi_regex:{r['name']}" for r in pi.REGEX_RULES]
    names += [f"pi_fuzzy:{n}" for n in (
        "exfiltration_intent", "task_switch", "injection_after_processing_task",
        "data_destination_url", "fake_conversation_turns")]
    return names


def split_rules(stats: Dict[str, dict], min_precision: float = 0.95, min_hits: int = 10) -> Dict[str, dict]:
    """
    stats: {rule: {"hits": int, "tp": int}} measured on the validation set.
    Returns {rule: {"hits", "tp", "precision", "decision", "reason"}}.
    A rule is blocking only if precision >= min_precision AND hits >= min_hits.
    """
    out = {}
    for rule, s in stats.items():
        hits, tp = s["hits"], s["tp"]
        precision = tp / hits if hits else None
        if hits < min_hits:
            decision, reason = "signal", f"only {hits} validation hits (< {min_hits})"
        elif precision < min_precision:
            decision, reason = "signal", f"precision {precision:.1%} < {min_precision:.0%}"
        else:
            decision, reason = "blocking", f"precision {precision:.1%} on {hits} hits"
        out[rule] = {"hits": hits, "tp": tp,
                     "precision": round(precision, 4) if precision is not None else None,
                     "decision": decision, "reason": reason}
    return out
