"""
gateway_state.py
Holds the gateway's pipeline. It is built once (at startup, via the app's
lifespan) and shared by every endpoint; tests can swap in a stub.
"""

from typing import Optional

from app.detectors.pipeline import build_gateway_pipeline

_pipeline = None


def get_pipeline():
    global _pipeline
    if _pipeline is None:
        _pipeline = build_gateway_pipeline()
    return _pipeline


def set_pipeline(pipeline: Optional[object]):
    """Replace the pipeline (tests). None means rebuild on next use."""
    global _pipeline
    _pipeline = pipeline
