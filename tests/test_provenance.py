"""Trusted metadata/store tests, including hostile and corrupted references."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.authorization.schemas import ResourceInfo
from app.provenance.models import DataArtifact, Sensitivity, TrustLevel
from app.provenance.store import ArtifactStore
from test_mcp import context


def fixture():
    store, principal = ArtifactStore(), context().principal
    store.register_session(principal, known_clean=True)
    resource = ResourceInfo(resource_id="order-a", tenant_id="tenant-a")
    return store, principal, resource


def test_server_issued_immutable_metadata_without_raw_content():
    store, principal, resource = fixture()
    item = store.record_order(principal, resource, {"synthetic-secret": "value"})
    assert item.sensitivity == Sensitivity.CONFIDENTIAL and item.trust_level == TrustLevel.TRUSTED
    assert item.source_resource_id == "order-a" and item.producer_tool == "support/get_order"
    assert item.created_at.utcoffset().total_seconds() == 0 and len(item.content_digest) == 64
    assert "synthetic-secret" not in item.model_dump_json()
    assert store.exposure(principal).sensitivity == Sensitivity.CONFIDENTIAL
    with pytest.raises(ValidationError): item.sensitivity = Sensitivity.PUBLIC


@pytest.mark.parametrize("change", [{"tenant": "tenant-b"}, {"session": "session-b"}])
def test_cross_boundary_artifact_and_lineage_reject(change):
    store, principal, resource = fixture()
    item = store.record_order(principal, resource, {})
    other = context(**change).principal
    for resolve in (store.resolve, store.lineage):
        with pytest.raises((KeyError, ValueError)): resolve(item.artifact_id, other)


@pytest.mark.parametrize("lookup", ["resolve", "lineage"])
def test_forged_artifact_id(lookup):
    store, principal, _ = fixture()
    with pytest.raises(KeyError): getattr(store, lookup)(uuid4(), principal)


def test_unknown_session_is_not_public_and_cannot_be_reset():
    store = ArtifactStore()
    principal = context().principal
    with pytest.raises(ValueError): store.exposure(principal)
    store.register_session(principal)
    assert store.exposure(principal).sensitivity == Sensitivity.UNKNOWN
    with pytest.raises(ValueError): store.register_session(principal, known_clean=True)


def test_parent_resolution_downgrade_and_trust_independent():
    store, principal, resource = fixture()
    public = store.record_order(principal, resource, {}, sensitivity=Sensitivity.PUBLIC, trust_level=TrustLevel.UNTRUSTED)
    assert public.sensitivity == Sensitivity.PUBLIC and public.trust_level == TrustLevel.UNTRUSTED
    with pytest.raises(ValueError): store.record_order(principal, resource, {}, parents=(public.artifact_id,))
    secret = store.record_order(principal, resource, {})
    with pytest.raises(ValueError):
        store.record_order(principal, resource, {}, parents=(secret.artifact_id,), sensitivity=Sensitivity.PUBLIC)
    with pytest.raises(KeyError): store.record_order(principal, resource, {}, parents=(uuid4(),))
    child = store.record_order(principal, resource, {}, parents=(secret.artifact_id,))
    assert [a.artifact_id for a in store.lineage(child.artifact_id, principal)] == [secret.artifact_id, child.artifact_id]


def test_duplicate_generated_id_does_not_overwrite(monkeypatch):
    store, principal, resource = fixture()
    item = store.record_order(principal, resource, {})
    monkeypatch.setattr("app.provenance.store.uuid4", lambda: item.artifact_id)
    with pytest.raises(ValueError): store.record_order(principal, resource, {})
    assert store.resolve(item.artifact_id, principal) == item


def test_lineage_cycle_corruption_detected():
    store, principal, resource = fixture()
    item = store.record_order(principal, resource, {})
    store._artifacts[item.artifact_id] = item.model_copy(update={"parent_artifact_ids": (item.artifact_id,)})
    with pytest.raises(ValueError): store.lineage(item.artifact_id, principal)
    with pytest.raises(ValueError): store.exposure(principal)


@pytest.mark.parametrize("field,value", [
    ("source_kind", "LLM_ASSERTED"), ("producer_tool", "arbitrary/tool"),
    ("sensitivity", "PUBLIC"), ("trust_level", "TRUSTED"),
    ("created_at", datetime(2026, 1, 1)), ("content_digest", "not-sha256"),
    ("parent_artifact_ids", []), ("agent_label", "PUBLIC"),
])
def test_strict_metadata_rejects_forged_types_or_extra_fields(field, value):
    store, principal, resource = fixture()
    data = store.record_order(principal, resource, {}).model_dump()
    data[field] = value
    with pytest.raises(ValidationError): DataArtifact.model_validate(data)


def test_concurrent_metadata_writes_preserve_every_artifact():
    store, principal, resource = fixture()
    with ThreadPoolExecutor(max_workers=8) as pool:
        items = list(pool.map(lambda _: store.record_order(principal, resource, {}), range(32)))
    assert len({a.artifact_id for a in items}) == 32
    state = store.exposure(principal)
    assert len(state.artifact_ids) == state.revision == 32


def test_wrong_resource_tenant_and_subject_collision():
    store, principal, _ = fixture()
    with pytest.raises(ValueError):
        store.record_order(principal, ResourceInfo(resource_id="order-b", tenant_id="tenant-b"), {})
    with pytest.raises(ValueError): store.exposure(context(subject="other-user").principal)


@pytest.mark.parametrize("corruption", ["missing", "downgrade", "tenant", "dropped-index", "poison"])
def test_inconsistent_state_is_unavailable(corruption):
    store, principal, resource = fixture()
    item = store.record_order(principal, resource, {})
    key = (principal.tenant_id, principal.session_id)
    state = store._sessions[key]
    if corruption == "missing": del store._artifacts[item.artifact_id]
    if corruption == "downgrade": store._sessions[key] = state.model_copy(update={"sensitivity": Sensitivity.PUBLIC})
    if corruption == "tenant": store._sessions[key] = state.model_copy(update={"tenant_id": "tenant-b"})
    if corruption == "dropped-index": store._sessions[key] = state.model_copy(update={"artifact_ids": ()})
    if corruption == "poison": store.poison(principal)
    with pytest.raises((KeyError, ValueError)): store.exposure(principal)
