"""Immutable metadata; constructing a model does not register authoritative data."""
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from app.authorization.schemas import Identifier, StrictModel


class Sensitivity(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    UNKNOWN = "UNKNOWN"


class TrustLevel(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class DataArtifact(StrictModel):
    artifact_id: UUID
    source_kind: Literal["TOOL_RESULT", "DERIVED", "RETRIEVED_DOCUMENT"]
    source_resource_id: Identifier
    producer_tool: Literal["support/get_order", "retrieval/host"]
    tenant_id: Identifier
    session_id: Identifier
    sensitivity: Sensitivity
    trust_level: TrustLevel
    parent_artifact_ids: tuple[UUID, ...]
    created_at: datetime
    content_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None

    @model_validator(mode="after")
    def producer_matches_source(self):
        if (self.source_kind == "RETRIEVED_DOCUMENT") != (self.producer_tool == "retrieval/host"):
            raise ValueError("invalid provenance producer")
        return self

    @field_validator("created_at")
    @classmethod
    def utc_only(cls, value):
        if value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
            raise ValueError("UTC timestamp required")
        return value


class Exposure(StrictModel):
    tenant_id: Identifier
    session_id: Identifier
    subject_id: Identifier
    sensitivity: Sensitivity
    artifact_ids: tuple[UUID, ...] = ()
    revision: int = Field(ge=0)
