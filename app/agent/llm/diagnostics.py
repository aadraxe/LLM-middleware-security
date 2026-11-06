"""Fixed metadata vocabulary. Never export provider text, codes or exceptions."""
from typing import Literal

DiagnosticCategory = Literal[
    "success", "request_invalid", "request_limit", "client_error", "transport_error", "timeout",
    "http_error", "response_limit", "invalid_json", "provider_error", "invalid_response_structure",
    "invalid_tool_call", "truncated_response", "invalid_final_answer", "cancelled",
]
ProviderErrorCategory = Literal[
    "authentication_error", "permission_error", "model_unavailable", "rate_limited", "quota_exceeded",
    "invalid_request", "tool_generation_failed", "server_error", "not_found", "redirect", "unclassified",
]

# Compare exact provider type/code tokens only. No message text is examined.
_ERROR_HINTS = {
    "invalid_api_key": "authentication_error", "authentication_error": "authentication_error",
    "permission_denied": "permission_error", "permission_error": "permission_error",
    "model_not_found": "model_unavailable", "unsupported_model": "model_unavailable",
    "model_decommissioned": "model_unavailable", "rate_limit_exceeded": "rate_limited",
    "rate_limit_error": "rate_limited", "insufficient_quota": "quota_exceeded",
    "invalid_request_error": "invalid_request", "invalid_request": "invalid_request",
    "tool_use_failed": "tool_generation_failed", "internal_server_error": "server_error",
    "server_error": "server_error",
}


def provider_error_hint(data, status=None):
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict):
        for key in ("code", "type"):
            value = error.get(key)
            if type(value) is str and value in _ERROR_HINTS:
                return _ERROR_HINTS[value]
    if status == 401: return "authentication_error"
    if status == 403: return "permission_error"
    if status == 404: return "not_found"  # HTTP 404 alone does not identify a model failure.
    if status == 429: return "rate_limited"
    if status in (400, 422): return "invalid_request"
    if status is not None and status >= 500: return "server_error"
    if status is not None and 300 <= status < 400: return "redirect"
    return "unclassified"
