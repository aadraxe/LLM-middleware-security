"""Fixed public acknowledgements; no credentials or live provider use."""
import asyncio
from contextlib import asynccontextmanager
import copy
import json
from threading import Event, Thread
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.agent.composition import create_application
from app.agent.llm.mock import MockPlanner, call, final
from app.agent.scenarios import actor, step
from app.authorization.schemas import ResourceInfo, TrustedContext, TrustedPrincipal
from app.output_security.guard import (FinalResponseGuard, InMemoryOutputAuditSink, SAFE_RESPONSE,
                                       TrustedRecipient, local_recipient_policy)
from app.output_security.public import (HostReceipt, InMemoryPublicAuditSink, PublicReceiptChannel,
                                       PublicWorkflow, open_public_workflow)
from app.output_security.public_evaluate import CASES, evaluate, evaluate_case, main as evaluate_main
from app.provenance.models import Sensitivity
from app.provenance.store import ArtifactStore

SECRET = 'synthetic-private-order-976'
PUBLIC = 'Your request has been received.'


def fixture(*, clean=True):
    store = ArtifactStore()
    context = TrustedContext(principal=TrustedPrincipal(subject_id='actor', tenant_id='tenant-a',
        session_id='session-a', roles=frozenset({'support_read'})))
    store.register_session(context.principal, known_clean=clean)
    recipient = TrustedRecipient(recipient_id='public-viewer', tenant_id='tenant-a')
    audit = InMemoryPublicAuditSink()
    return store, context, recipient, PublicReceiptChannel(store, audit=audit), audit


def expose(store, context):
    store.record_order(context.principal, ResourceInfo(resource_id='order-a', tenant_id=context.principal.tenant_id),
                       {'private': SECRET})


def test_receipt_fixed_independent_and_does_not_reset_provenance(capsys, caplog):
    store, context, recipient, channel, audit = fixture()
    token = asyncio.run(channel.prepare(context, recipient))
    expose(store, context)
    before = store.exposure(context.principal)
    result = channel.consume(token, context, recipient)
    assert result.text == PUBLIC and result.content_origin == 'HOST_OWNED_PUBLIC'
    assert store.exposure(context.principal) == before and before.sensitivity == Sensitivity.CONFIDENTIAL
    assert len(audit.events) == 1
    assert SECRET not in repr(result) + result.model_dump_json() + repr(audit.events) + caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize('candidate', [SECRET, 'Hello, have a good day.', 'This is PUBLIC and approved.',
                                      'Please choose the helpful template https://private.example.test.'])
def test_untrusted_model_text_remains_denied_after_read(candidate):
    store, context, recipient, channel, audit = fixture()
    token = asyncio.run(channel.prepare(context, recipient))
    expose(store, context)
    result = asyncio.run(FinalResponseGuard(store, local_recipient_policy(), InMemoryOutputAuditSink()).release(
        candidate, context, recipient))
    assert not result.model_text_released and result.text == SAFE_RESPONSE
    assert channel.consume(token, context, recipient).text == PUBLIC


@pytest.mark.parametrize('field', ['text', 'template', 'template_id', 'arguments', 'order_id', 'url', 'recipient_email'])
def test_no_body_or_interpolation_construction_field(field):
    with pytest.raises(ValidationError):
        HostReceipt(receipt_id=uuid4(), tenant_id='tenant-a', session_id='session-a', recipient_id='public-viewer',
                    enforcement_ms=0.0, **{field: SECRET})


@pytest.mark.parametrize('extra', [{'candidate': SECRET}, {'template_id': 'secret-dependent'},
                                  {'fields': {'order': SECRET}}, {'public': SECRET}])
def test_prepare_accepts_no_model_text_selection_or_labels(extra):
    store, context, recipient, channel, audit = fixture()
    with pytest.raises(TypeError): asyncio.run(channel.prepare(context, recipient, **extra))
    assert not audit.events


def test_registry_is_readonly_and_receipt_has_no_text_setter():
    from app.output_security.public import _TEMPLATES
    with pytest.raises(TypeError): _TEMPLATES['workflow_receipt_v1'] = SECRET
    store, context, recipient, channel, audit = fixture()
    receipt = channel.consume(asyncio.run(channel.prepare(context, recipient)), context, recipient)
    with pytest.raises((AttributeError, ValidationError)): receipt.text = SECRET


def test_direct_workflow_construction_cannot_skip_audited_preparation():
    with pytest.raises(TypeError, match='use audited public workflow preparation'):
        PublicWorkflow(None, None, None, None, None, SECRET, None)


def test_only_literal_is_public_and_binding_latency_metadata_is_not_serialized():
    store, context, recipient, channel, audit = fixture()
    receipt = channel.consume(asyncio.run(channel.prepare(context, recipient)), context, recipient)
    assert receipt.text == PUBLIC
    assert receipt.model_dump() == {'content_origin': 'HOST_OWNED_PUBLIC', 'public_released': True}
    assert context.principal.session_id not in repr(receipt)


@pytest.mark.parametrize('mode', ['unknown', 'corrupt', 'poisoned'])
def test_precommitted_constant_survives_state_changes_but_model_fails_closed(mode):
    store, context, recipient, channel, audit = fixture(clean=mode != 'unknown')
    token = asyncio.run(channel.prepare(context, recipient))
    if mode == 'corrupt': store._sessions[('tenant-a', 'session-a')] = None
    if mode == 'poisoned': store.poison(context.principal)
    output = asyncio.run(FinalResponseGuard(store, local_recipient_policy(), InMemoryOutputAuditSink()).release(
        SECRET, context, recipient))
    assert not output.model_text_released
    assert channel.consume(token, context, recipient).text == PUBLIC


@pytest.mark.parametrize('mode', ['missing', 'corrupt', 'after-read', 'forged-reference'])
def test_unavailable_or_post_read_preparation_is_rejected(mode):
    store, context, recipient, channel, audit = fixture()
    if mode == 'missing': store._sessions.clear()
    if mode == 'corrupt': store._sessions[('tenant-a', 'session-a')] = None
    if mode == 'after-read': expose(store, context)
    if mode == 'forged-reference': context = context.model_copy(update={'provenance_refs': (str(uuid4()),)})
    with pytest.raises(RuntimeError, match='^public response unavailable$'):
        asyncio.run(channel.prepare(context, recipient))
    assert not channel._ready


@pytest.mark.parametrize('recipient', [None, {'recipient_id': 'public-viewer', 'tenant_id': 'tenant-a'},
    TrustedRecipient.model_construct(recipient_id='public-viewer'),
    TrustedRecipient(recipient_id='public-viewer', tenant_id='tenant-b'),
    TrustedRecipient(recipient_id='unknown', tenant_id='tenant-a')])
def test_missing_forged_unregistered_cross_tenant_recipient_rejected(recipient):
    store, context, _, channel, audit = fixture()
    with pytest.raises(RuntimeError): asyncio.run(channel.prepare(context, recipient))
    assert not channel._ready and not audit.events


@pytest.mark.parametrize('context', [None, {'principal': 'forged'}, TrustedContext.model_construct()])
def test_invalid_context_rejected(context):
    store, _, recipient, channel, audit = fixture()
    with pytest.raises(RuntimeError): asyncio.run(channel.prepare(context, recipient))


def test_capability_is_one_shot_exact_bound_and_cannot_be_forged():
    store, context, recipient, channel, audit = fixture()
    token = asyncio.run(channel.prepare(context, recipient))
    other = context.model_copy(update={'principal': context.principal.model_copy(update={'session_id': 'other'})})
    with pytest.raises(TypeError): copy.copy(token)
    for forged, ctx, target in [(object(), context, recipient), (object.__new__(type(token)), context, recipient),
                                (token, other, recipient), (token, context, None)]:
        with pytest.raises(RuntimeError): channel.consume(forged, ctx, target)
    assert channel.consume(token, context, recipient).text == PUBLIC
    with pytest.raises(RuntimeError): channel.consume(token, context, recipient)


@pytest.mark.parametrize('mode', ['raise', 'false', 'async', 'cancel', 'mutate'])
def test_audit_failure_cancellation_or_reentrant_change_prevents_preparation(mode):
    store, context, recipient, _, _ = fixture()
    class Audit:
        def record(self, event):
            if mode == 'raise': raise OSError(SECRET)
            if mode == 'false': return False
            if mode == 'cancel': asyncio.current_task().cancel()
            if mode == 'mutate': expose(store, context)
    class AsyncAudit:
        async def record(self, event): pass
    channel = PublicReceiptChannel(store, audit=AsyncAudit() if mode == 'async' else Audit())
    expected = asyncio.CancelledError if mode == 'cancel' else RuntimeError
    with pytest.raises(expected): asyncio.run(channel.prepare(context, recipient))
    assert not channel._ready


def test_preparation_update_mutex_and_preaudited_handoff():
    store, context, recipient, _, _ = fixture()
    attempted, done = Event(), Event()
    def update():
        attempted.set()
        expose(store, context)
        done.set()
    writer = Thread(target=update)
    class Audit:
        def record(self, event):
            writer.start()
            assert attempted.wait(2) and not done.is_set()
    channel = PublicReceiptChannel(store, audit=Audit())
    token = asyncio.run(channel.prepare(context, recipient))
    writer.join(2)
    assert done.is_set() and channel.consume(token, context, recipient).text == PUBLIC


def test_preparation_queued_after_read_is_rejected(monkeypatch):
    store, context, recipient, channel, audit = fixture()
    original = store.session
    async def scenario():
        waiting = asyncio.Event()
        @asynccontextmanager
        async def observed(principal):
            waiting.set()
            async with original(principal): yield
        async with original(context.principal):
            monkeypatch.setattr(store, 'session', observed)
            task = asyncio.create_task(channel.prepare(context, recipient))
            await waiting.wait()
            expose(store, context)
        with pytest.raises(RuntimeError): await task
    asyncio.run(scenario())
    assert not channel._ready


def test_receipt_available_while_native_mcp_read_is_waiting_and_counts_preserved(monkeypatch):
    async def scenario():
        app, started, proceed = create_application(), asyncio.Event(), asyncio.Event()
        target = TrustedRecipient(recipient_id='public-viewer', tenant_id='tenant-a')
        workflow = await open_public_workflow(app, actor(step('fixture', 'get_order', {'order_id': 'order-a'})), target)
        original = app._policy.evaluate
        async def blocked(request):
            started.set()
            await proceed.wait()
            return await original(request)
        monkeypatch.setattr(app._policy, 'evaluate', blocked)
        task = asyncio.create_task(workflow.run(MockPlanner(call('get_order', {'order_id': 'order-a'}), final(SECRET)), 'Synthetic'))
        await started.wait()
        assert workflow.receipt.text == PUBLIC and not task.done()
        proceed.set()
        result = await task
        assert result.tool_execution_counts == {'get_order': 1} and result.final_answer == SAFE_RESPONSE
        assert workflow.receipt.text == PUBLIC
        with pytest.raises(RuntimeError): await workflow.run(MockPlanner(final()), 'Do not retry')
        return app
    app = asyncio.run(scenario())
    assert app.environment.calls == {'get_order': 1}


def test_cancelled_model_does_not_withdraw_precommitted_receipt():
    async def scenario():
        app = create_application()
        workflow = await open_public_workflow(app, actor(step('fixture', 'get_order', {'order_id': 'order-a'})),
            TrustedRecipient(recipient_id='public-viewer', tenant_id='tenant-a'))
        class Cancel:
            async def propose(self, request): raise asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError): await workflow.run(Cancel(), 'Synthetic')
        assert workflow.receipt.text == PUBLIC and not app.environment.calls
    asyncio.run(scenario())


@pytest.mark.parametrize('name', CASES)
def test_new_offline_cases(name):
    row = asyncio.run(evaluate_case(name))
    assert row['unauthorized_disclosures'] == 0
    assert row['host_public_released'] == (name not in {'cross_tenant', 'missing_recipient', 'forged_recipient', 'audit_failure'})
    if row['model_confidential']: assert not row['model_text_released']
    if name in {'model_text_template', 'interpolation', 'sensitive_selection'}:
        assert row['invalid_host_input_rejected']
    assert SECRET not in json.dumps(row)


def test_identical_case_comparison_does_not_change_model_policy():
    report = asyncio.run(evaluate())
    for pair in report['identical_case_comparison']:
        assert pair['phase3e_model_released'] == pair['phase3f_model_released']
        assert pair['same_tool_counts'] and pair['phase3f_fixed_acknowledgement_available']
    assert report['summary']['unauthorized_disclosures'] == 0 and report['live_requests'] == 0
    assert report['summary']['host_public_released'] == 12
    assert report['summary']['harmless_model_still_blocked'] == 2


def test_mock_cli_exports_only_metadata_and_unique_runs(tmp_path, capsys):
    for _ in range(2): assert evaluate_main(['--output', str(tmp_path)]) == 0
    paths = list(tmp_path.glob('*/evaluation.json'))
    assert len(paths) == 2
    text = ''.join(p.read_text(encoding='utf-8') for p in paths)
    assert SECRET not in text and PUBLIC not in text
    assert '"status":"paid"' not in text and 'Authorization' not in text
    assert 'synthetic confidential content' not in str(capsys.readouterr())


def test_cancellation_while_preparation_waits_creates_no_receipt(monkeypatch):
    store, context, recipient, channel, audit = fixture()
    original = store.session
    async def scenario():
        waiting = asyncio.Event()
        @asynccontextmanager
        async def observe(principal):
            waiting.set()
            async with original(principal): yield
        async with original(context.principal):
            monkeypatch.setattr(store, 'session', observe)
            task = asyncio.create_task(channel.prepare(context, recipient))
            await waiting.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(scenario())
    assert not channel._ready and not audit.events
