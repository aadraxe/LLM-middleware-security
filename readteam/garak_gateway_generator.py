"""
garak_gateway_generator.py
Adapter that lets Garak fire its probes THROUGH the middleware gateway
instead of directly at a model.

Garak calls `gateway_generate(prompt)`. We run the prompt through the
ThreatPipeline. If the pipeline blocks it, we return a refusal string
(the attack was stopped at the gateway). If it allows it, we forward to
the LLM and return the model output (the attack got through the gateway).

This way Garak's own detectors measure how many attacks reach the model —
which is exactly the defended-vs-undefended comparison we want.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.detectors.pipeline import ThreatPipeline
from app.services.llm_service import call_llm

_pipeline = ThreatPipeline()

# Set REDTEAM_BASELINE=1 to bypass the gateway and hit the model directly
# (this produces the undefended baseline run).
BASELINE_MODE = os.environ.get("REDTEAM_BASELINE", "0") == "1"

BLOCK_RESPONSE = "[GATEWAY BLOCKED] Request refused by security middleware."


def gateway_generate(prompt: str) -> list[str]:
    """Garak function-generator entrypoint. Returns a list of outputs."""
    if BASELINE_MODE:
        # Undefended: straight to the model
        return [call_llm(prompt)]

    result = _pipeline.analyze(prompt)
    if not result.allowed:
        # Attack stopped at the gateway — model never sees it
        return [BLOCK_RESPONSE]

    # Attack passed the gateway — forward to the model
    return [call_llm(prompt)]
