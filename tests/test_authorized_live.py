"""Explicit local credentials and approved runner tested offline with fake keys."""
import asyncio
import json
import os

import httpx
import pytest

from app.agent.llm import authorized
from app.agent.llm.groq import GroqPlanner
from app.agent.llm.usage import ProviderExchange, TokenUsage
from app.agent.llm.contracts import Limits
from app.agent.llm.live import run_evaluation
from app.agent.llm.mock import MockPlanner, final


def test_local_key_is_private_and_does_not_interpolate_or_change_environment(tmp_path, capsys, caplog):
    path = tmp_path / '.env'
    path.write_text('UNRELATED="private-content"\nGROQ_API_KEY="synthetic-private-key"\n')
    before = dict(os.environ)
    key = authorized.load_local_key(path)
    assert key.get_secret_value() == 'synthetic-private-key'
    assert dict(os.environ) == before
    assert 'synthetic-private-key' not in repr(key) + caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize('content', ['', 'GROQ_API_KEY=', 'GROQ_API_KEY=${OTHER}',
    'GROQ_API_KEY=a\nGROQ_API_KEY=b', 'GROQ_API_KEY="bad key"', 'X=' + 'x' * 65537],
    ids=['missing', 'empty', 'interpolation', 'duplicate', 'whitespace', 'oversize'])
def test_bad_local_credential_is_sanitized(content, tmp_path):
    path = tmp_path / '.env'
    path.write_text(content)
    with pytest.raises(RuntimeError, match='^local Groq credential unavailable$'):
        authorized.load_local_key(path)


def test_approval_required_before_reading_key(monkeypatch):
    monkeypatch.setattr(authorized, 'load_local_key', lambda *a: pytest.fail('credential read'))
    assert authorized.main(['--credential-file', '.env']) == 2


@pytest.mark.parametrize('usage', [None, TokenUsage(prompt_tokens=32769, completion_tokens=1, total_tokens=32770),
    TokenUsage(prompt_tokens=1, completion_tokens=1025, total_tokens=1026)])
def test_unexpected_or_missing_usage_stops(usage):
    guard = authorized.UsageGuard()
    with pytest.raises(RuntimeError, match='provider usage stop'):
        guard.check(ProviderExchange(request_attempted=True, usage=usage))
    assert guard.stopped


def test_aggregate_usage_stop():
    guard = authorized.UsageGuard()
    exchange = ProviderExchange(request_attempted=True,
        usage=TokenUsage(prompt_tokens=25000, completion_tokens=1, total_tokens=25001))
    for _ in range(3): guard.check(exchange)
    with pytest.raises(RuntimeError): guard.check(exchange)


@pytest.mark.parametrize('answer', ['I completed the requested tool work.', 'I cannot help with that request.',
                                    'Please clarify the task.'])
def test_final_without_tools_is_not_assumed_to_be_refusal_or_success(answer):
    report = asyncio.run(run_evaluation(authorized.scenarios()[:1], Limits(), 1,
        lambda: MockPlanner(final(answer)), evidence_source='offline_fixture'))
    row = report['rows'][0]
    assert row['final_behavior'] == 'NO_TOOL_PROPOSAL' and row['final_intent'] == 'UNRESOLVED'
    assert row['actions'][0]['classification_reason'] == 'FINAL_NO_TOOL_REQUEST'
    assert row['mcp_calls'] == 0 and not row['complete_legitimate_task_success']
    assert row['prohibited_operations_correctly_blocked'] == 0
    assert answer not in json.dumps(report)


def test_approved_entry_point_uses_fixture_and_exports_only_metadata(tmp_path, monkeypatch):
    credential = tmp_path / '.env'
    credential.write_text('GROQ_API_KEY=synthetic-private-key')
    selected = authorized.scenarios()[:1]
    monkeypatch.setattr(authorized, 'scenarios', lambda: selected)
    calls = []
    def handler(request):
        calls.append(request)
        message, finish = {'role': 'assistant', 'content': 'Private final response'}, 'stop'
        if len(calls) == 1:
            message.update(content=None, tool_calls=[{'id': 'read', 'type': 'function', 'function':
                {'name': 'get_order', 'arguments': '{"order_id":"order-a"}'}}])
            finish = 'tool_calls'
        return httpx.Response(200, json={'choices': [{'message': message, 'finish_reason': finish}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 3, 'total_tokens': 13}})
    monkeypatch.setattr(authorized, 'GroqPlanner', lambda config: GroqPlanner(config, transport=httpx.MockTransport(handler)))
    output = tmp_path / 'results'
    assert authorized.main(['--approved-live', '--credential-file', str(credential), '--output', str(output)]) == 0
    files = list(output.glob('*/*'))
    text = ''.join(p.read_text() for p in files)
    assert 'synthetic-private-key' not in text and 'Private final response' not in text
    report = json.loads(next(p for p in files if p.name == 'evaluation.json').read_text())
    assert report['evidence_source'] == 'injected_transport'
    assert report['summary']['model_calls'] == len(calls) == 2
    assert report['rows'][0]['final_behavior'] == 'GOAL_REACHED'
    assert report['rows'][0]['final_intent'] == 'UNRESOLVED'


@pytest.mark.parametrize('failure', ['rate_limit', 'usage_limit'])
def test_approved_runner_stops_without_dispatch_retry_or_next_scenario(failure, tmp_path, monkeypatch):
    credential = tmp_path / '.env'
    credential.write_text('GROQ_API_KEY=synthetic-private-key')
    selected = authorized.scenarios()[:2]
    monkeypatch.setattr(authorized, 'scenarios', lambda: selected)
    calls = []
    def handler(request):
        calls.append(request)
        if failure == 'rate_limit':
            return httpx.Response(429, json={'error': {'type': 'rate_limit_error', 'message': 'private-error'}})
        return httpx.Response(200, json={'choices': [{'finish_reason': 'tool_calls', 'message': {
            'role': 'assistant', 'content': None, 'tool_calls': [{'id': 'read', 'type': 'function',
                'function': {'name': 'get_order', 'arguments': '{"order_id":"order-a"}'}}]}}],
            'usage': {'prompt_tokens': 32769, 'completion_tokens': 1, 'total_tokens': 32770}})
    monkeypatch.setattr(authorized, 'GroqPlanner', lambda config: GroqPlanner(config, transport=httpx.MockTransport(handler)))
    output = tmp_path / 'results'
    assert authorized.main(['--approved-live', '--credential-file', str(credential), '--output', str(output)]) == 0
    report = json.loads(next(output.glob('*/evaluation.json')).read_text())
    assert len(calls) == report['summary']['model_calls'] == 1
    assert report['rows'][0]['execution_counts'] == {} and report['rows'][0]['mcp_calls'] == 0
    assert report['rows'][1]['final_response_status'] == 'NOT_RUN_AFTER_FAILURE'
    assert report['experiment']['usage_stop'] == (failure == 'usage_limit')
