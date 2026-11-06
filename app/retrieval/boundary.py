"""Tenant-authorized host retrieval -> exposure/audit -> lower-trust planner data."""
import asyncio
from datetime import datetime, timezone
import inspect
import time
from threading import Lock
from types import MappingProxyType
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field
from app.authorization.schemas import Identifier, StrictModel, TrustedContext, canonical_json
from app.agent.llm.contracts import Limits, PlannerRequest, RetrievedPassage
from app.provenance.models import Sensitivity, TrustLevel


class Document(StrictModel):
    """Host catalogue record; never deserialize agent/document content into it."""
    source_id: Identifier
    tenant_id: Identifier
    sensitivity: Sensitivity | None
    trust_level: TrustLevel | None
    text: str = Field(max_length=8192, repr=False)


class SyntheticRetriever:
    def __init__(self, documents):
        snapshot = {}
        for document in documents:
            if not isinstance(document, Document): raise TypeError("trusted catalogue record required")
            document = Document.model_validate(document)
            if document.source_id in snapshot: raise ValueError("duplicate source")
            snapshot[document.source_id] = document
        self._documents = MappingProxyType(snapshot)

    def select(self, context, sources):
        # Authorize every selected record before returning any of its content.
        if 'support_read' not in context.principal.roles: raise PermissionError()
        documents = tuple(self._documents[source] for source in sources)
        if any(d.tenant_id != context.principal.tenant_id for d in documents): raise PermissionError()
        return documents


class RetrievalAuditEvent(StrictModel):
    event_type: Literal['retrieval_delivery'] = 'retrieval_delivery'
    request_id: UUID
    timestamp: datetime
    tenant_id: Identifier
    session_id: Identifier
    artifact_ids: tuple[UUID, ...]
    source_ids: tuple[Identifier, ...]
    status: Literal['AUTHORIZED_FOR_DELIVERY', 'DELIVERED_TO_PLANNER', 'NOT_DELIVERED']
    reason_code: Literal['RETRIEVAL_ALLOWED', 'RETRIEVAL_DENIED', 'RETRIEVAL_UNAVAILABLE']


class InMemoryRetrievalAudit:
    def __init__(self): self._mutex, self._events = Lock(), []

    @property
    def events(self):
        with self._mutex: return tuple(self._events)

    def record(self, event):
        event = RetrievalAuditEvent.model_validate(event)
        with self._mutex: self._events.append(event)


def _cancelled():
    if asyncio.current_task().cancelling(): raise asyncio.CancelledError()


class RetrievalPlan:
    """Trusted configuration, not an agent action or remotely selectable mode."""
    def __init__(self, retriever, sources, audit):
        if not isinstance(retriever, SyntheticRetriever) or not isinstance(sources, tuple):
            raise TypeError('trusted retriever and immutable source selection required')
        if not 1 <= len(sources) <= 4 or len(set(sources)) != len(sources):
            raise ValueError('invalid retrieval selection')
        self._retriever, self._sources, self._audit = retriever, sources, audit
        self._metrics_lock, self._samples = Lock(), []

    @property
    def preparation_ms(self):
        with self._metrics_lock: return tuple(self._samples)

    def bind(self, delegate, context, store, *, limits=None):
        if not isinstance(context, TrustedContext): raise TypeError('trusted context required')
        return _BoundPlanner(self, delegate, TrustedContext.model_validate(context), store,
                             Limits() if limits is None else Limits.model_validate(limits))


class _BoundPlanner:
    def __init__(self, plan, delegate, context, store, limits):
        self._plan, self._delegate, self._context, self._store, self._limits = plan, delegate, context, store, limits
        self._passages = None

    async def propose(self, request):
        started = time.perf_counter()
        request_id, artifacts, sources = uuid4(), (), ()
        principal = self._context.principal
        def audit(status, reason):
            acceptance = self._plan._audit.record(RetrievalAuditEvent(request_id=request_id,
                timestamp=datetime.now(timezone.utc), tenant_id=principal.tenant_id, session_id=principal.session_id,
                artifact_ids=artifacts, source_ids=sources, status=status, reason_code=reason))
            if acceptance is not None:
                if inspect.iscoroutine(acceptance): acceptance.close()
                raise ValueError()
        _cancelled()
        try:
            async with self._store.session(principal):
                with self._store.dispatch_context():
                    state = self._store.exposure(principal)
                    if self._passages is None:
                        documents = self._plan._retriever.select(self._context, self._plan._sources)
                        sources = tuple(d.source_id for d in documents)
                        passages = []
                        for document in documents:
                            item = self._store.record_document(principal, document.source_id, document.tenant_id,
                                document.text, sensitivity=document.sensitivity or Sensitivity.UNKNOWN,
                                trust_level=document.trust_level or TrustLevel.UNKNOWN)
                            passages.append(RetrievedPassage(artifact_id=item.artifact_id, source_id=document.source_id,
                                                             text=document.text))
                        self._passages = tuple(passages)
                    artifacts = tuple(p.artifact_id for p in self._passages)
                    sources = tuple(p.source_id for p in self._passages)
                    for artifact in artifacts: self._store.resolve(artifact, principal)
                    state = self._store.exposure(principal)
                    enriched = PlannerRequest.model_validate(request.model_copy(update={'retrieved': self._passages}))
                    if len(canonical_json(enriched.model_dump(mode='json')).encode()) > self._limits.max_prompt_bytes:
                        raise ValueError()
                    if time.perf_counter()-started > self._limits.model_timeout_seconds:
                        raise ValueError()
                    audit('AUTHORIZED_FOR_DELIVERY', 'RETRIEVAL_ALLOWED')
                    if self._store.exposure(principal) != state: raise ValueError()
                    _cancelled()
                    if time.perf_counter()-started > self._limits.model_timeout_seconds:
                        raise ValueError()
        except PermissionError:
            try: audit('NOT_DELIVERED', 'RETRIEVAL_DENIED')
            except Exception: pass
            raise RuntimeError('retrieval unavailable') from None
        except Exception:
            self._store.poison(principal)
            try: audit('NOT_DELIVERED', 'RETRIEVAL_UNAVAILABLE')
            except Exception: pass
            raise RuntimeError('retrieval unavailable') from None
        finally:
            with self._plan._metrics_lock:
                self._plan._samples.append((time.perf_counter()-started)*1000)
        cancelled = False
        try:
            # This is the actual lower-trust request handoff, not external-provider proof.
            return await self._delegate.propose(enriched)
        except asyncio.CancelledError:
            cancelled = True
            raise
        finally:
            try: audit('DELIVERED_TO_PLANNER', 'RETRIEVAL_ALLOWED')
            except Exception:
                self._store.poison(principal)
                if not cancelled:
                    raise RuntimeError('retrieval delivery audit unavailable') from None
