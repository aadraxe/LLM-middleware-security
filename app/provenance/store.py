"""Append-only, synchronized metadata store. No raw tool content is retained."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
from threading import Lock, RLock
from uuid import UUID, uuid4

from app.authorization.schemas import TrustedPrincipal, canonical_json
from .models import DataArtifact, Exposure, Sensitivity, TrustLevel


def join_sensitivity(values):
    values = set(values)
    if Sensitivity.UNKNOWN in values:
        return Sensitivity.UNKNOWN
    return max(values, key=lambda s: (Sensitivity.PUBLIC, Sensitivity.INTERNAL, Sensitivity.CONFIDENTIAL).index(s))


class ArtifactStore:
    def __init__(self):
        self._mutex = RLock()
        self._artifacts = {}
        self._sessions = {}
        self._locks = {}
        self._poisoned = set()

    @staticmethod
    def _key(principal):
        principal = TrustedPrincipal.model_validate(principal)
        return principal.tenant_id, principal.session_id

    def register_session(self, principal, *, known_clean=False):
        """Trusted harness attests a fresh session, never resets existing exposure."""
        key = self._key(principal)
        if type(known_clean) is not bool:
            raise ValueError("explicit boolean session assertion required")
        with self._mutex:
            if key in self._sessions or key in self._poisoned:
                raise ValueError("session already registered")
            self._sessions[key] = Exposure(tenant_id=principal.tenant_id, session_id=principal.session_id,
                subject_id=principal.subject_id, sensitivity=Sensitivity.PUBLIC if known_clean else Sensitivity.UNKNOWN,
                revision=0)

    @asynccontextmanager
    async def session(self, principal):
        key = self._key(principal)
        with self._mutex:
            lock = self._locks.setdefault(key, Lock())
        # Nonblocking acquisition avoids blocking the event loop and is safe
        # across threads/loops. Cancellation while waiting owns no lock.
        while not lock.acquire(blocking=False):
            await asyncio.sleep(0)
        try:
            yield
        finally:
            lock.release()

    def poison(self, principal):
        with self._mutex:
            self._poisoned.add(self._key(principal))

    def dispatch_context(self):
        """No awaits permitted: atomic final check/dispatch versus metadata writes."""
        return self._mutex

    def exposure(self, principal):
        key = self._key(principal)
        with self._mutex:
            if key in self._poisoned or key not in self._sessions:
                raise ValueError("unavailable session provenance")
            state = Exposure.model_validate(self._sessions[key])
            if (state.tenant_id, state.session_id, state.subject_id) != (*key, principal.subject_id):
                raise ValueError("session binding mismatch")
            artifacts = [self.resolve(a, principal) for a in state.artifact_ids]
            expected = {a.artifact_id for a in self._artifacts.values()
                        if (a.tenant_id, a.session_id) == key}
            if (set(state.artifact_ids) != expected or len(set(state.artifact_ids)) != len(state.artifact_ids)
                    or state.revision != len(state.artifact_ids)):
                raise ValueError("inconsistent artifact index")
            for item in artifacts:
                self.lineage(item.artifact_id, principal)
            # Known-clean is an explicit harness assertion; known records can
            # only increase exposure. Validate every referenced record on read.
            if artifacts and join_sensitivity([state.sensitivity, *(a.sensitivity for a in artifacts)]) != state.sensitivity:
                raise ValueError("inconsistent session classification")
            return state

    def resolve(self, artifact_id, principal):
        with self._mutex:
            artifact = DataArtifact.model_validate(self._artifacts[artifact_id])
            if (artifact.tenant_id, artifact.session_id) != self._key(principal) or artifact.artifact_id != artifact_id:
                raise ValueError("artifact binding mismatch")
            return artifact

    def lineage(self, artifact_id, principal):
        with self._mutex:
            result, visiting, visited = [], set(), set()
            def visit(current):
                if current in visiting:
                    raise ValueError("lineage cycle")
                if current in visited:
                    return
                visiting.add(current)
                item = self.resolve(current, principal)
                for parent in item.parent_artifact_ids:
                    visit(parent)
                visiting.remove(current)
                visited.add(current)
                result.append(item)
            visit(artifact_id)
            return tuple(result)

    def record_order(self, principal, resource, content, *, parents=(), sensitivity=Sensitivity.CONFIDENTIAL,
                     trust_level=TrustLevel.TRUSTED):
        """Trusted labeling interface; never exposed as MCP arguments.

        The guard always supplies CONFIDENTIAL/TRUSTED. Optional labels support
        trusted derived-artifact experiments, with monotonic parent labels.
        """
        with self._mutex:
            if not isinstance(sensitivity, Sensitivity) or not isinstance(trust_level, TrustLevel):
                raise ValueError("trusted enum labels required")
            state = self.exposure(principal)
            if resource is None or resource.tenant_id != principal.tenant_id:
                raise ValueError("invalid resource ownership")
            ancestors = [a for p in parents for a in self.lineage(p, principal)]
            effective = join_sensitivity([sensitivity, *(p.sensitivity for p in ancestors)])
            if effective != sensitivity:
                raise ValueError("sensitivity downgrade")
            if any(p.trust_level != TrustLevel.TRUSTED for p in ancestors) and trust_level == TrustLevel.TRUSTED:
                raise ValueError("trust upgrade")
            artifact_id = uuid4()
            if artifact_id in self._artifacts:
                raise ValueError("duplicate artifact ID")
            item = DataArtifact(artifact_id=artifact_id, source_kind="DERIVED" if parents else "TOOL_RESULT",
                source_resource_id=resource.resource_id, producer_tool="support/get_order",
                tenant_id=principal.tenant_id, session_id=principal.session_id, sensitivity=sensitivity,
                trust_level=trust_level, parent_artifact_ids=tuple(parents), created_at=datetime.now(timezone.utc),
                content_digest=hashlib.sha256(canonical_json(content).encode()).hexdigest())
            updated = state.model_copy(update={"sensitivity": join_sensitivity([state.sensitivity, sensitivity]),
                "artifact_ids": (*state.artifact_ids, artifact_id), "revision": state.revision + 1})
            self._artifacts[artifact_id] = item
            self._sessions[self._key(principal)] = updated
            return item

    def record_document(self, principal, source_id, tenant_id, content, *, sensitivity, trust_level):
        """Trusted host retrieval only; text never supplies these source labels."""
        with self._mutex:
            state = self.exposure(principal)
            if tenant_id != principal.tenant_id or not isinstance(sensitivity, Sensitivity) or not isinstance(trust_level, TrustLevel):
                raise ValueError("invalid retrieved source metadata")
            artifact_id = uuid4()
            if artifact_id in self._artifacts:
                raise ValueError("duplicate artifact ID")
            item = DataArtifact(artifact_id=artifact_id, source_kind="RETRIEVED_DOCUMENT",
                source_resource_id=source_id, producer_tool="retrieval/host", tenant_id=tenant_id,
                session_id=principal.session_id, sensitivity=sensitivity, trust_level=trust_level,
                parent_artifact_ids=(), created_at=datetime.now(timezone.utc),
                content_digest=hashlib.sha256(canonical_json(content).encode()).hexdigest())
            self._artifacts[artifact_id] = item
            self._sessions[self._key(principal)] = state.model_copy(update={
                "sensitivity": join_sensitivity([state.sensitivity, sensitivity]),
                "artifact_ids": (*state.artifact_ids, artifact_id), "revision": state.revision + 1})
            return item
