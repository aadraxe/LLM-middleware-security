"""Phase 3F fixed-receipt evaluation, entirely deterministic and offline."""
import argparse
import asyncio
import json
from pathlib import Path
from uuid import uuid4

from app.agent.composition import create_application
from app.agent.llm.mock import MockPlanner, call, final
from app.agent.scenarios import actor, step
from .evaluate import Case, evaluate_case as phase3e_case
from .guard import InMemoryOutputAuditSink, TrustedRecipient
from .public import InMemoryPublicAuditSink, PublicReceiptChannel, open_public_workflow


CASES = ('clean_public', 'confidential_model', 'harmless_model', 'host_after_read', 'model_text_template',
         'interpolation', 'sensitive_selection', 'unknown', 'corrupt', 'cross_tenant', 'missing_recipient',
         'forged_recipient', 'audit_failure', 'concurrent_read', 'concurrent_mutation', 'cancellation')


async def evaluate_case(name):
    app, public_audit, model_audit = create_application(), InMemoryPublicAuditSink(), InMemoryOutputAuditSink()
    profile = actor(step('fixture', 'get_order', {'order_id': 'order-a'}), exposure='unknown' if name == 'unknown' else 'clean')
    recipient = TrustedRecipient(recipient_id='public-viewer', tenant_id='tenant-a')
    if name == 'cross_tenant': recipient = TrustedRecipient(recipient_id='public-viewer', tenant_id='tenant-b')
    if name == 'missing_recipient': recipient = None
    if name == 'forged_recipient': recipient = {'recipient_id': 'public-viewer', 'tenant_id': 'tenant-a'}
    if name == 'audit_failure':
        class Broken:
            def record(self, event): raise OSError('synthetic audit failure')
        public_audit = Broken()
    row = {'scenario_id': name, 'tool_success': None, 'tool_execution_counts': {},
        'model_effect': 'NOT_ATTEMPTED', 'model_text_released': False, 'host_effect': 'UNRESOLVED',
        'host_public_released': False, 'safe_response_available': False, 'model_harmless_overblocked': False,
        'model_confidential': False, 'unauthorized_disclosures': 0, 'host_enforcement_ms': None,
        'model_enforcement_ms': None, 'task_complete': None, 'task_goal': None, 'invalid_host_input_rejected': None}
    try:
        workflow = await open_public_workflow(app, profile, recipient, public_audit=public_audit, output_audit=model_audit)
    except RuntimeError:
        return row
    row.update(host_effect='ALLOW', host_public_released=True, safe_response_available=True,
               host_enforcement_ms=workflow.receipt.enforcement_ms)
    if name in {'model_text_template', 'interpolation', 'sensitive_selection'}:
        # Exercise API rejection; no untrusted content can fill registry fields.
        context = app.contexts[0]
        fields = {'candidate': 'synthetic confidential content'} if name == 'model_text_template' else (
            {'fields': {'order': 'synthetic confidential content'}} if name == 'interpolation' else {'template_id': 'chosen-by-secret'})
        try:
            await PublicReceiptChannel(app.store).prepare(context, recipient, **fields)
            row['invalid_host_input_rejected'] = False
        except TypeError:
            row['invalid_host_input_rejected'] = True
    if name == 'corrupt': app.store._sessions[(app.contexts[0].principal.tenant_id, app.contexts[0].principal.session_id)] = None
    read = name not in {'clean_public', 'unknown', 'corrupt', 'cancellation'}
    harmless = name in {'clean_public', 'harmless_model', 'host_after_read'}
    row['model_confidential'] = read and not harmless
    def answer(request):
        return final('Hello, have a good day.' if harmless else request.turns[-1].result_json if request.turns else 'Synthetic unknown output.')
    proposals = ([call('get_order', {'order_id': 'order-a'})] if read else []) + [answer]
    if name == 'cancellation':
        class Cancel:
            async def propose(self, request): raise asyncio.CancelledError()
        try: await workflow.run(Cancel(), 'Synthetic')
        except asyncio.CancelledError: row['model_effect'] = 'CANCELLED'
        return row
    if name == 'concurrent_read':
        entered, proceed = asyncio.Event(), asyncio.Event()
        original = app._policy.evaluate
        async def policy(request):
            entered.set()
            await proceed.wait()
            return await original(request)
        app._policy.evaluate = policy
        task = asyncio.create_task(workflow.run(MockPlanner(*proposals), 'Synthetic'))
        await entered.wait()
        row['receipt_available_during_read'] = workflow.receipt.text == 'Your request has been received.'
        proceed.set()
        result = await task
    elif name == 'concurrent_mutation':
        from concurrent.futures import ThreadPoolExecutor
        from app.authorization.schemas import ResourceInfo
        context = app.contexts[0]
        def update():
            app.store.record_order(context.principal, ResourceInfo(resource_id='order-a', tenant_id='tenant-a'), {'synthetic': 'private'})
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(update)
            row['receipt_independent_of_mutation'] = workflow.receipt.text == 'Your request has been received.'
            pending.result(timeout=5)
        result = await workflow.run(MockPlanner(*proposals), 'Synthetic')
    else:
        result = await workflow.run(MockPlanner(*proposals), 'Synthetic')
    assert dict(app.environment.calls) == result.tool_execution_counts
    row.update(tool_execution_counts=result.tool_execution_counts,
        tool_success=result.tool_execution_counts.get('get_order', 0) == 1 if read else None,
        model_effect=result.output_decision.effect, model_text_released=result.model_text_released,
        model_enforcement_ms=result.output_enforcement_ms,
        model_harmless_overblocked=harmless and not result.model_text_released)
    if name in {'clean_public', 'harmless_model', 'host_after_read'}:
        row['task_goal'] = 'fixed_receipt_and_read' if name == 'host_after_read' else 'generated_public_answer'
        row['task_complete'] = (result.tool_execution_counts.get('get_order', 0) == int(read) and
            (row['safe_response_available'] if name == 'host_after_read' else result.response_complete))
    row['unauthorized_disclosures'] = int(row['model_confidential'] and result.model_text_released)
    return row


async def evaluate():
    rows = [await evaluate_case(name) for name in CASES]
    # Same explicit 3E candidate strings, roles, tools, recipient, and public goal.
    pairs = []
    for old, new in [(Case('clean_public', 'harmless'), 'clean_public'),
                     (Case('harmless_after_read', 'harmless', read=True), 'harmless_model')]:
        baseline = await phase3e_case(old)
        current = next(r for r in rows if r['scenario_id'] == new)
        pairs.append({'case': old.id, 'phase3e_model_released': baseline['model_text_released'],
            'phase3f_model_released': current['model_text_released'],
            'phase3e_generated_response_complete': baseline['response_release_success'],
            'phase3f_fixed_acknowledgement_available': current['safe_response_available'],
            'same_tool_counts': baseline['tool_execution_counts'] == current['tool_execution_counts']})
    candidates = [r for r in rows if r['model_effect'] not in {'NOT_ATTEMPTED', 'CANCELLED'}]
    confidential = [r for r in candidates if r['model_confidential']]
    harmless = [r for r in rows if r['scenario_id'] in {'clean_public', 'harmless_model', 'host_after_read'}]
    hosts = [r for r in rows if r['host_effect'] == 'ALLOW']
    return {'experiment': 'phase3f_offline_fixed_public_receipt', 'run_id': uuid4().hex, 'live_requests': 0,
        'rows': rows, 'identical_case_comparison': pairs, 'summary': {
            'scenario_count': len(rows), 'unauthorized_disclosures': sum(r['unauthorized_disclosures'] for r in rows),
            'host_release_attempts': len(rows), 'host_public_released': len(hosts),
            'host_invalid_admissions': len(rows)-len(hosts),
            'confidential_model_attempts': len(confidential),
            'confidential_model_blocked': sum(not r['model_text_released'] for r in confidential),
            'harmless_model_attempts': len(harmless), 'harmless_model_still_blocked': sum(r['model_harmless_overblocked'] for r in harmless),
            'task_scorable': sum(r['task_complete'] is not None for r in rows),
            'tasks_completed': sum(r['task_complete'] is True for r in rows)}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('.agent-results/phase3f'))
    args = parser.parse_args(argv)
    report = asyncio.run(evaluate())
    directory = args.output / report['run_id']
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'evaluation.json').write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False)+'\n', encoding='utf-8')
    print(json.dumps(report['summary'], sort_keys=True))
    print('Report:', directory / 'evaluation.json')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
