"""
secure_retrieve.py
Stage 3: retrieve chunks, then screen each one for prompt injection
using the existing security pipeline BEFORE it can reach the LLM.

This defends against INDIRECT prompt injection — malicious instructions
hidden inside documents that the RAG system retrieves and would otherwise
feed straight to the model.

Usage:
    python -m rag.secure_retrieve "what is prompt injection?"
"""

import sys
from rag.query import retrieve
from app.detectors.prompt_injection_detector import PromptInjectionDetector

# Reuse the SAME detector that guards the chat gateway
_injection_detector = PromptInjectionDetector()


def secure_retrieve(question: str, n_results: int = 3):
    """
    Retrieve chunks, then screen each for injection.
    Returns (clean_chunks, flagged_chunks).
    """
    hits = retrieve(question, n_results)

    clean = []
    flagged = []

    for hit in hits:
        # Run the retrieved chunk's TEXT through the injection detector.
        # We're treating the document content as untrusted input.
        result = _injection_detector.detect(hit["text"])

        if result.allowed:
            clean.append(hit)
        else:
            flagged.append({
                **hit,
                "threat": result.threat_type,
                "risk_score": result.risk_score,
                "triggered_rules": result.triggered_rules,
            })

    return clean, flagged


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python -m rag.secure_retrieve "your question here"')
        sys.exit(1)

    question = sys.argv[1]
    clean, flagged = secure_retrieve(question)

    print(f"\nQuestion: {question}\n")
    print(f"Clean chunks (safe to send to LLM): {len(clean)}")
    for hit in clean:
        print(f"  [OK] source={hit['source']} distance={hit['distance']:.3f}")

    print(f"\nFlagged chunks (BLOCKED — possible injection): {len(flagged)}")
    for hit in flagged:
        print(f"  [BLOCKED] source={hit['source']} risk={hit['risk_score']} rules={hit['triggered_rules']}")
    print()