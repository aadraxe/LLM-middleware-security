"""Optional provider-reported metadata, never authorization or estimated billing."""
from pydantic import Field, model_validator
from app.authorization.schemas import StrictModel
from .diagnostics import DiagnosticCategory, ProviderErrorCategory


class TokenUsage(StrictModel):
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)

    @model_validator(mode="after")
    def consistent(self):
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("inconsistent provider usage")
        return self


class ProviderExchange(StrictModel):
    request_attempted: bool
    usage: TokenUsage | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    diagnostic_category: DiagnosticCategory | None = None
    provider_error_category: ProviderErrorCategory | None = None


def read_usage(value):
    try:
        # Provider timing/cache metadata is outside this deliberately small schema.
        return TokenUsage.model_validate({k: value[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens")})
    except Exception:
        return None


def summarize_usage(exchanges):
    attempted = [e for e in exchanges if e.request_attempted]
    valid = [e.usage for e in attempted if e.usage is not None]
    return {"provider_request_attempts": len(attempted), "usage_covered_calls": len(valid),
            "usage_complete": bool(attempted) and len(valid) == len(attempted),
            "provider_reported_tokens": {k: sum(getattr(v, k) for v in valid)
                for k in ("prompt_tokens", "completion_tokens", "total_tokens")} if valid else None,
            "provider_diagnostics": [{"provider_call": index + 1,
                **e.model_dump(exclude={"usage"})} for index, e in enumerate(exchanges)],
            "estimated_cost": None}
