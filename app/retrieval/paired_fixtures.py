"""HTTP response fixtures, not live model behavior or runtime fallback logic."""
import json
import argparse
import asyncio
from pathlib import Path
from uuid import uuid4
import httpx
from pydantic import SecretStr
from app.agent.llm.groq import GroqConfig, GroqPlanner
from .paired_dataset import MODEL, VERSION, cases
from .scenarios import CONFIDENTIAL, PUBLIC_HOURS


def response(*,name=None,arguments=None,answer='Task complete.',call_id='fixture-call',usage=True):
    message={'role':'assistant','content':answer}
    if name:
        message.update(content=None,tool_calls=[{'id':call_id,'type':'function','function':
            {'name':name,'arguments':json.dumps(arguments)}}])
    result={'choices':[{'finish_reason':'tool_calls' if name else 'stop','message':message}]}
    if usage: result['usage']={'prompt_tokens':100,'completion_tokens':20,'total_tokens':120}
    return httpx.Response(200,json=result)


def fixture_factory(case):
    position=0
    def handle(request):
        nonlocal position
        position+=1
        if position==1:
            if case.variant=='malicious':
                if case.pair_id in {'faq','refund'}:
                    return response(name='issue_refund',arguments={'order_id':'order-a','amount_cents':5001})
                if case.pair_id in {'order','mixed'}:
                    return response(name='get_order',arguments={'order_id':'order-b'})
                if case.pair_id=='bypass': return response(name='create_authorization_only_application',arguments={})
                if case.pair_id in {'final','downgrade'}: return response(answer=CONFIDENTIAL)
            if case.goal=='faq': return response(answer=PUBLIC_HOURS)
            if case.goal=='refund': return response(name='issue_refund',arguments={'order_id':'order-a','amount_cents':100})
            if case.goal=='order' or case.variant=='malicious': return response(name='get_order',arguments={'order_id':'order-a'})
            return response(name='send_email',arguments={'order_id':'order-a','recipient':'support@example.test','body':PUBLIC_HOURS})
        if case.pair_id=='email' and case.variant=='malicious' and position==2:
            return response(name='send_email',arguments={'order_id':'order-a','recipient':'support@example.test','body':CONFIDENTIAL},call_id='email')
        return response(answer=PUBLIC_HOURS if case.goal=='faq' else 'Order-a is paid.' if case.goal=='order' else 'Task complete.')
    return GroqPlanner(GroqConfig(enabled=True,model=MODEL,api_key=SecretStr('synthetic-offline-key')),
                       transport=httpx.MockTransport(handle))


async def run_fixture_matrix():
    """Eight independent capped fixture batches; never a live campaign."""
    from .paired_benchmark import run_benchmark
    from .paired_scoring import paired_differences, summarize
    reports=[]
    for pair in dict.fromkeys(c.pair_id for c in cases()):
        reports.append(await run_benchmark(tuple(c for c in cases() if c.pair_id==pair),fixture_factory))
    rows=[r for report in reports for r in report['rows']]
    return {'schema_version':'1','dataset_version':VERSION,'run_id':uuid4().hex,'provider':'groq','model':MODEL,
        'evidence_source':'offline_http_fixture_matrix','live_evaluation_status':'NOT RUN',
        'fixture_batches':[{'pair_id':r['rows'][0]['pair_id'],'maximum_calls':r['maximum_model_calls'],
            'actual_fixture_requests':r['summary']['provider_request_attempts']} for r in reports],
        'rows':rows,'paired_differences':paired_differences(rows),
        'summary':{**summarize(rows),'fixture_http_requests':sum(r['summary']['provider_request_attempts'] for r in reports),
            'fixture_usage_covered_calls':sum(r['summary']['usage_covered_calls'] for r in reports),
            'fixture_reported_tokens':{k:sum(r['summary']['provider_reported_tokens'][k] for r in reports
                if r['summary']['provider_reported_tokens'] is not None) for k in ['prompt_tokens','completion_tokens','total_tokens']},
            'live_api_requests':0}}


def main(argv=None):
    from .paired_benchmark import write_reports
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('.agent-results/phase4b-fixtures'))
    args=parser.parse_args(argv)
    report=asyncio.run(run_fixture_matrix())
    output=write_reports(report,args.output)
    print(json.dumps(report['summary'],sort_keys=True))
    print('Offline fixture reports:',output)
    return 0


if __name__=='__main__': raise SystemExit(main())
