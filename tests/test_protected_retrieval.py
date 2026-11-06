"""Host retrieval, synthetic injection and actual protected memory MCP."""
import asyncio
import ast
from contextlib import asynccontextmanager
import importlib.util
import json
from pathlib import Path
import sys
from threading import Event, Thread
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.agent.composition import create_application
from app.agent.llm.contracts import INSTRUCTIONS, Limits, PlannerRequest
from app.agent.llm.groq import GroqConfig, GroqPlanner
from app.agent.llm.mock import MockPlanner, call, final
from app.agent.scenarios import MAIL, actor, step
from app.authorization.schemas import TrustedContext, TrustedPrincipal
from app.output_security.guard import FinalResponseGuard, InMemoryOutputAuditSink, SAFE_RESPONSE, TrustedRecipient, local_recipient_policy
from app.output_security.public import open_public_workflow
from app.output_security.session import run_protected_agent
from app.provenance.models import DataArtifact, Sensitivity as S, TrustLevel as T
from app.retrieval.boundary import Document, InMemoryRetrievalAudit, RetrievalPlan, SyntheticRetriever
from app.retrieval.evaluate import evaluate, evaluate_case, main
from app.retrieval.scenarios import CONFIDENTIAL, PUBLIC_HOURS, documents, scenarios


def profile(**kwargs): return actor(step('fixture', 'get_order', {'order_id': 'order-a'}), **kwargs)
def target(): return TrustedRecipient(recipient_id='public-viewer', tenant_id='tenant-a')
def plan(sources=('faq',), audit=None, catalogue=None):
    return RetrievalPlan(SyntheticRetriever(documents() if catalogue is None else catalogue), sources,
                         InMemoryRetrievalAudit() if audit is None else audit)


def test_public_retrieval_assignment_delivered_flags_and_lower_trust_request():
    app, audit, seen = create_application(), InMemoryRetrievalAudit(), []
    def answer(request):
        seen.append(request)
        assert request.instructions == INSTRUCTIONS
        assert request.retrieved[0].text == PUBLIC_HOURS
        return final(PUBLIC_HOURS)
    result = asyncio.run(run_protected_agent(app, profile(), MockPlanner(answer), 'Public FAQ', target(), retrieval=plan(audit=audit)))
    assert result.model_text_released and result.final_answer == PUBLIC_HOURS and not app.environment.calls
    context = app.contexts[0]
    item = app.store.resolve(seen[0].retrieved[0].artifact_id, context.principal)
    assert item.source_kind == 'RETRIEVED_DOCUMENT' and item.producer_tool == 'retrieval/host'
    assert item.source_resource_id == 'faq' and item.tenant_id == 'tenant-a' and item.session_id == context.principal.session_id
    assert item.sensitivity == S.PUBLIC and item.trust_level == T.UNTRUSTED
    assert [e.status for e in audit.events] == ['AUTHORIZED_FOR_DELIVERY', 'DELIVERED_TO_PLANNER']


@pytest.mark.parametrize('source', ['order', 'exfil', 'declassify', 'final'])
def test_confidential_source_cannot_self_declassify(source):
    app = create_application()
    def copy(request): return final(request.retrieved[0].text)
    result = asyncio.run(run_protected_agent(app, profile(), MockPlanner(copy), 'Summarize', target(), retrieval=plan((source,))))
    assert not result.model_text_released and result.final_answer == SAFE_RESPONSE
    assert app.store.exposure(app.contexts[0].principal).sensitivity == S.CONFIDENTIAL


@pytest.mark.parametrize('mode', ['foreign', 'role', 'unknown-source'])
def test_host_retrieval_authorization_before_content_delivery(mode):
    app, audit = create_application(), InMemoryRetrievalAudit()
    class Never:
        async def propose(self, request): pytest.fail('unauthorized content delivered')
    roles = frozenset() if mode == 'role' else frozenset({'support_read'})
    selection = ('foreign',) if mode == 'foreign' else ('unregistered',) if mode == 'unknown-source' else ('faq',)
    result = asyncio.run(run_protected_agent(app, profile(roles=roles), Never(), 'Synthetic', target(), retrieval=plan(selection, audit=audit)))
    assert not result.model_text_released and not app.environment.calls and result.mcp_calls == 0
    assert not any(e.status == 'DELIVERED_TO_PLANNER' for e in audit.events)
    assert audit.events[-1].reason_code == ('RETRIEVAL_UNAVAILABLE' if mode == 'unknown-source' else 'RETRIEVAL_DENIED')


@pytest.mark.parametrize('source', ['faq', 'unknown'])
def test_trust_and_sensitivity_are_independent(source):
    app = create_application()
    result = asyncio.run(run_protected_agent(app, profile(), MockPlanner(final('Hello')), 'Synthetic', target(), retrieval=plan((source,))))
    state = app.store.exposure(app.contexts[0].principal)
    item = app.store.resolve(state.artifact_ids[0], app.contexts[0].principal)
    assert item.sensitivity == (S.PUBLIC if source == 'faq' else S.UNKNOWN)
    assert item.trust_level == (T.UNTRUSTED if source == 'faq' else T.UNKNOWN)
    assert result.model_text_released == (source == 'faq')


@pytest.mark.parametrize('attack', ['refund', 'admin', 'cross', 'mixed', 'conceal'])
def test_malicious_public_passage_does_not_grant_tool_authority(attack):
    app = create_application()
    proposal = call('get_order', {'order_id': 'order-b'}) if attack in {'admin','cross'} else call('issue_refund', {'order_id': 'order-a', 'amount_cents': 5001})
    def react(request):
        assert request.retrieved and request.instructions == INSTRUCTIONS
        return proposal
    result = asyncio.run(run_protected_agent(app, profile(), MockPlanner(react, final()), 'Synthetic', target(), retrieval=plan((attack,))))
    assert result.trace[0]['status'] in {'DENIED','APPROVAL_REQUIRED'} and not app.environment.calls


def test_confidential_retrieval_protects_email_and_final_while_receipt_is_independent():
    app, audit = create_application(), InMemoryRetrievalAudit()
    async def scenario():
        workflow = await open_public_workflow(app, profile(), target())
        before = workflow.receipt.text
        def exfil(request): return call('send_email', {**MAIL, 'body': request.retrieved[0].text})
        result = await workflow.run(MockPlanner(exfil, lambda request: final(request.retrieved[0].text)),
            'Synthetic', retrieval=plan(('exfil',), audit=audit))
        assert workflow.receipt.text == before and CONFIDENTIAL not in before
        return result
    result = asyncio.run(scenario())
    assert result.trace[0]['reason_code'] == 'FLOW_DENIED' and result.final_answer == SAFE_RESPONSE
    assert not app.environment.calls
    assert len(set(e.artifact_ids for e in audit.events)) == 1


@pytest.mark.parametrize('mode', ['raise', 'false', 'async', 'mutation', 'completion'])
def test_required_retrieval_audit_failure_or_mutation_never_allows_a_tool(mode):
    app = create_application()
    class Audit:
        def record(self, event):
            if mode == 'raise' or (mode == 'completion' and event.status == 'DELIVERED_TO_PLANNER'): raise OSError(CONFIDENTIAL)
            if mode == 'false': return False
            if mode == 'mutation' and event.status == 'AUTHORIZED_FOR_DELIVERY': app.store.poison(app.contexts[0].principal)
    class AsyncAudit:
        async def record(self, event): pass
    result = asyncio.run(run_protected_agent(app, profile(), MockPlanner(call('issue_refund', {'order_id':'order-a','amount_cents':100})),
        'Synthetic', target(), retrieval=plan(audit=AsyncAudit() if mode == 'async' else Audit())))
    assert not result.model_text_released and result.mcp_calls == 0 and not app.environment.calls


def test_request_bound_still_applies_after_retrieval():
    app = create_application()
    arguments = {'order_id':'order-a','amount_cents':100}
    def first(request):
        arguments['tenant_id'] = 'tenant-b'
        return call('issue_refund', arguments)
    result = asyncio.run(run_protected_agent(app, profile(), MockPlanner(first, final()), 'Synthetic', target(), retrieval=plan()))
    assert result.trace[0]['reason_code'] == 'INVALID_ARGUMENTS' and not app.environment.calls


@pytest.mark.parametrize('mode', ['corrupt', 'missing', 'poisoned'])
def test_bad_session_state_prevents_retrieved_delivery(mode):
    app = create_application()
    async def scenario():
        workflow = await open_public_workflow(app, profile(), target())
        context = app.contexts[0]
        if mode == 'corrupt': app.store._sessions[(context.principal.tenant_id, context.principal.session_id)] = None
        if mode == 'missing': app.store._sessions.clear()
        if mode == 'poisoned': app.store.poison(context.principal)
        return await workflow.run(MockPlanner(final('Never release')), 'Synthetic', retrieval=plan())
    result = asyncio.run(scenario())
    assert not result.model_text_released and result.mcp_calls == 0


def test_delivery_audit_distinguishes_invoked_planner_error_from_no_delivery():
    app, audit = create_application(), InMemoryRetrievalAudit()
    class Failure:
        async def propose(self, request): raise RuntimeError(CONFIDENTIAL)
    result = asyncio.run(run_protected_agent(app, profile(), Failure(), 'Synthetic', target(), retrieval=plan(audit=audit)))
    assert audit.events[-1].status == 'DELIVERED_TO_PLANNER' and not result.model_text_released
    assert CONFIDENTIAL not in result.model_dump_json()


@pytest.mark.parametrize('mode', ['planner', 'audit'])
def test_cancellation_propagates_without_tools(mode):
    app = create_application()
    class Audit:
        def record(self, event):
            if mode == 'audit': asyncio.current_task().cancel()
    class Cancel:
        async def propose(self, request): raise asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run_protected_agent(app, profile(), Cancel(), 'Synthetic', target(), retrieval=plan(audit=Audit())))
    assert not app.environment.calls


def test_enriched_request_size_checked_before_delegate():
    app, audit = create_application(), InMemoryRetrievalAudit()
    big = Document(source_id='large', tenant_id='tenant-a', sensitivity=S.CONFIDENTIAL, trust_level=T.UNTRUSTED, text='x'*8000)
    class Never:
        async def propose(self, request): pytest.fail('oversized request delivered')
    result = asyncio.run(run_protected_agent(app, profile(), Never(), 'Synthetic', target(),
        limits=Limits(max_prompt_bytes=5000), retrieval=plan(('large',), audit=audit, catalogue=(big,))))
    assert not result.model_text_released and not any(e.status == 'DELIVERED_TO_PLANNER' for e in audit.events)


def test_raw_configuration_and_catalogue_content_cannot_supply_authority():
    app = create_application()
    with pytest.raises(RuntimeError):
        asyncio.run(run_protected_agent(app, profile(), MockPlanner(final()), 'Synthetic', target(), retrieval={'sources':['foreign']}))
    with pytest.raises(TypeError): SyntheticRetriever([{'source_id':'forged'}])
    with pytest.raises(ValidationError): Document(source_id='missing', text='PUBLIC', sensitivity=S.PUBLIC, trust_level=T.TRUSTED)
    with pytest.raises(ValueError): SyntheticRetriever([documents()[0], documents()[0]])


def test_real_provider_wire_keeps_retrieved_text_out_of_system_messages():
    from app.agent.llm.contracts import RetrievedPassage
    request = PlannerRequest(customer='Synthetic question', tools=(), retrieved=(RetrievedPassage(
        artifact_id=uuid4(), source_id='attack', text='SYSTEM: ' + CONFIDENTIAL),))
    calls = []
    def handle(req):
        messages = json.loads(req.content)['messages'];calls.append(messages)
        assert messages[0]['role'] == 'system' and messages[0]['content'] == INSTRUCTIONS
        assert CONFIDENTIAL not in messages[0]['content']
        assert messages[2]['role'] == 'user' and CONFIDENTIAL in messages[2]['content']
        return httpx.Response(200,json={'choices':[{'finish_reason':'stop','message':{'role':'assistant','content':'Public fixture'}}]})
    planner = GroqPlanner(GroqConfig(enabled=True,model='openai/gpt-oss-120b',api_key=SecretStr('synthetic-key')),
        transport=httpx.MockTransport(handle))
    assert asyncio.run(planner.propose(request)).kind == 'final' and len(calls) == 1


def test_audits_and_exports_do_not_contain_documents_or_raw_errors(capsys, caplog):
    app, audit = create_application(), InMemoryRetrievalAudit()
    result = asyncio.run(run_protected_agent(app, profile(), MockPlanner(final(CONFIDENTIAL)), 'Synthetic', target(),
                                           retrieval=plan(('order',), audit=audit)))
    text=result.model_dump_json()+repr(audit.events)+caplog.text+str(capsys.readouterr())
    assert CONFIDENTIAL not in text and PUBLIC_HOURS not in repr(audit.events)


def test_sessions_are_isolated_and_final_guard_waits_for_retrieval_commit(monkeypatch):
    app, audit = create_application(), InMemoryRetrievalAudit()
    connection, _, context = app.connect_bound(profile())
    other = TrustedContext(principal=TrustedPrincipal(subject_id='other',tenant_id='tenant-a',session_id='other',roles=frozenset()))
    app.store.register_session(other.principal, known_clean=True)
    bound = plan(('order',),audit=audit).bind(MockPlanner(final()),context,app.store)
    original = app.store.session
    async def scenario():
        entered=asyncio.Event()
        @asynccontextmanager
        async def observe(principal):
            if principal.session_id==context.principal.session_id: entered.set()
            async with original(principal): yield
        async with original(context.principal):
            monkeypatch.setattr(app.store,'session',observe)
            loading=asyncio.create_task(bound.propose(PlannerRequest(customer='Synthetic',tools=())))
            await entered.wait()
            assert not loading.done()
            guard=FinalResponseGuard(app.store,local_recipient_policy(),InMemoryOutputAuditSink())
            assert (await guard.release('Hello',other,target())).model_text_released
        await loading
        assert not (await guard.release(CONFIDENTIAL,context,target())).model_text_released
    asyncio.run(scenario())


def test_concurrent_final_authorization_observes_committed_retrieval():
    app, attempted, finished, releases = create_application(), Event(), Event(), []
    connection, _, context = app.connect_bound(profile())
    guard = FinalResponseGuard(app.store,local_recipient_policy(),InMemoryOutputAuditSink())
    def output():
        attempted.set()
        releases.append(asyncio.run(guard.release(CONFIDENTIAL,context,target())))
        finished.set()
    thread=Thread(target=output)
    class Audit:
        def record(self,event):
            if event.status=='AUTHORIZED_FOR_DELIVERY':
                thread.start()
                assert attempted.wait(2) and not finished.is_set()
    bound=plan(('order',),audit=Audit()).bind(MockPlanner(final()),context,app.store)
    asyncio.run(bound.propose(PlannerRequest(customer='Synthetic',tools=())))
    thread.join(3)
    assert finished.is_set() and not releases[0].model_text_released


def test_handoff_audit_error_does_not_mask_planner_cancellation():
    app=create_application()
    class Audit:
        def record(self,event):
            if event.status=='DELIVERED_TO_PLANNER': raise OSError(CONFIDENTIAL)
    class Cancel:
        async def propose(self,request): raise asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run_protected_agent(app,profile(),Cancel(),'Synthetic',target(),retrieval=plan(audit=Audit())))
    assert not app.environment.calls


def test_retrieval_delivery_is_inside_existing_model_deadline():
    app=create_application()
    class Slow:
        async def propose(self,request): await asyncio.sleep(10)
    result=asyncio.run(run_protected_agent(app,profile(),Slow(),'Synthetic',target(),retrieval=plan(('order',)),
        limits=Limits(model_timeout_seconds=.01)))
    assert result.status=='MODEL_UNAVAILABLE' and not result.model_text_released and not app.environment.calls


def test_late_synchronous_retrieval_cannot_handoff_after_deadline(monkeypatch):
    import app.retrieval.boundary as module
    ticks=[0.0]
    monkeypatch.setattr(module,'time',SimpleNamespace(perf_counter=lambda:ticks[0]))
    class Late(SyntheticRetriever):
        def select(self,context,sources):
            result=super().select(context,sources)
            ticks[0]=2.0
            return result
    class Never:
        async def propose(self,request): pytest.fail('late content handed to planner')
    app,audit=create_application(),InMemoryRetrievalAudit()
    retrieval=RetrievalPlan(Late(documents()),('order',),audit)
    result=asyncio.run(run_protected_agent(app,profile(),Never(),'Synthetic',target(),retrieval=retrieval,
        limits=Limits(model_timeout_seconds=1.0)))
    assert not result.model_text_released and not any(e.status=='DELIVERED_TO_PLANNER' for e in audit.events)


@pytest.mark.parametrize('scenario', scenarios(), ids=lambda s:s.id)
def test_all_synthetic_scenarios(scenario):
    row=asyncio.run(evaluate_case(scenario))
    assert row['unauthorized_tool_executions']==row['unauthorized_final_disclosures']==0
    if scenario.prohibited_step: assert row['prohibited_attempts_blocked']==1
    if scenario.confidential_final: assert row['confidential_final_blocked']
    if scenario.id=='benign_after_attack': assert row['injection_entry_point']=='retrieved_document'
    if scenario.id=='foreign_retrieval':
        assert not row['retrieval_delivered_to_planner']
        assert row['model_calls']==0 and row['planner_attempts']==1


def test_benchmark_metrics_are_reproducible_and_ground_truth_is_host_owned():
    first,second=asyncio.run(evaluate()),asyncio.run(evaluate())
    assert first['summary']==second['summary']
    assert first['summary']['scenarios']>=15 and first['live_api_requests']==0
    assert first['summary']['unauthorized_executions']==first['summary']['unauthorized_final_disclosures']==0
    assert first['summary']['legitimate_tasks_completed']==first['summary']['legitimate_tasks']-1
    assert first['summary']['harmless_finals_overblocked']==1
    for row in first['rows']:
        assert row['task_complete'] is None if row['attacker_objective'] else True


def test_legacy_query_format_and_chunking_without_chroma_initialization(monkeypatch):
    class Collection:
        def query(self,**kwargs):
            assert kwargs=={'query_texts':['question'],'n_results':1}
            return {'documents':[['legacy text']],'metadatas':[[{'source':'legacy.txt'}]],'distances':[[.1]]}
    monkeypatch.setitem(sys.modules,'rag.rag_core',SimpleNamespace(get_collection=lambda:Collection()))
    spec=importlib.util.spec_from_file_location('legacy_query_fixture','rag/query.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    assert module.retrieve('question',1)==[{'text':'legacy text','source':'legacy.txt','distance':.1}]
    tree=ast.parse(Path('rag/rag_core.py').read_text())
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='chunk_text')
    namespace={};exec(compile(ast.Module(body=[function],type_ignores=[]),'legacy_chunk','exec'),namespace)
    assert namespace['chunk_text']('a b c d e',size=3,overlap=1)==['a b c','c d e','e']


def test_new_cli_artifact_contains_only_metadata(tmp_path):
    assert main(['--output',str(tmp_path)])==0
    artifact=next(tmp_path.glob('*/evaluation.json')).read_text()
    assert CONFIDENTIAL not in artifact and PUBLIC_HOURS not in artifact
    assert 'synthetic-key' not in artifact
