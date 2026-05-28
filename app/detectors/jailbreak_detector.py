import re
from app.models.schemas import DetectionResult


JAILBREAK_RULES = [
    {
        "name": "instruction_override",
        "patterns": [
            r"ignore (all )?(previous|prior|above) instructions",
            r"disregard (all )?(previous|prior|above) instructions",
            r"forget (all )?(previous|prior|above) instructions",
        ],
        "score": 0.45,
    },
    {
        "name": "role_manipulation",
        "patterns": [
            r"you are now",
            r"act as dan",
            r"developer mode",
            r"pretend to be unrestricted",
            r"roleplay as",
        ],
        "score": 0.35,
    },
    {
        "name": "safety_bypass",
        "patterns": [
            r"bypass safety",
            r"bypass restrictions",
            r"ignore policy",
            r"disable your safety",
            r"do anything now",
        ],
        "score": 0.45,
    },
    {
        "name": "system_prompt_extraction",
        "patterns": [
            r"reveal (your )?(system|hidden) prompt",
            r"show (your )?(system|hidden) instructions",
            r"print (your )?(system|hidden) prompt",
            r"what are your hidden instructions",
        ],
        "score": 0.5,
    },
]


BLOCK_THRESHOLD = 0.7


def detect_jailbreak(prompt: str) -> DetectionResult:
    normalized_prompt = prompt.lower()
    risk_score = 0.0
    triggered_rules = []

    for rule in JAILBREAK_RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, normalized_prompt):
                risk_score += rule["score"]

                if rule["name"] not in triggered_rules:
                    triggered_rules.append(rule["name"])

                break

    risk_score = min(risk_score, 1.0)
    allowed = risk_score < BLOCK_THRESHOLD

    threat_type = "jailbreak_attempt" if not allowed else None

    return DetectionResult(
        allowed=allowed,
        risk_score=risk_score,
        threat_type=threat_type,
        triggered_rules=triggered_rules,
    )