"""Stage A offline-first paired benchmark; Stage B needs separate authorization."""
import asyncio
import csv
import getpass
import json
from pathlib import Path
import statistics
import sys
from threading import Lock
import time
from uuid import uuid4
import warnings

from pydantic import SecretStr
from app.agent.composition import create_application
from app.agent.llm.authorized import load_local_key
from app.agent.llm.contracts import Decision, Limits
from app.agent.llm.groq import GroqConfig, GroqPlanner
from app.agent.llm.live import SafeParser
from app.agent.llm.usage import summarize_usage
from app.agent.scenarios import actor, step
from app.output_security.guard import RecipientPolicy, TrustedRecipient
from app.output_security.public import open_public_workflow
from app.output_security.session import run_protected_agent
from app.provenance.models import Sensitivity
from .boundary import InMemoryRetrievalAudit, RetrievalPlan, SyntheticRetriever
from .paired_dataset import MODEL, VERSION, cases
from .paired_scoring import final_class, paired_differences, score, summarize
from .scenarios import PUBLIC_HOURS

CONFIRMATION = 'RUN SYNTHETIC RAG PILOT WITH GROQ'


class Budget:
    def __init__(self, maximum):
        if type(maximum) is not int or not 1<=maximum<=12: raise ValueError('pilot budget must be 1 to 12')
        self.maximum,self.used,self._mutex=maximum,0,Lock()

    def take(self):
        with self._mutex:
            if self.used>=self.maximum: return False
            self.used+=1
            return True


class ObservedPlanner:
    """Private transient proposal inspection, never a grant or exported transcript."""
    def __init__(self,delegate,budget):
        self.delegate,self.budget=delegate,budget
        self.calls,self.attempts,self.budget_exhausted=0,0,False
        self.proposals,self.delegate_ms={},{}
        self.final_classification,self.final_is_hours='NOT_FINAL',False

    async def propose(self,request):
        self.attempts+=1
        if not self.budget.take():
            self.budget_exhausted=True
            raise RuntimeError('pilot budget exhausted')
        self.calls+=1
        started=time.perf_counter()
        try: value=await self.delegate.propose(request)
        finally: self.delegate_ms[self.attempts]=(time.perf_counter()-started)*1000
        try:
            decision=Decision.model_validate(value)
            if decision.kind=='tool': self.proposals[self.attempts]=decision.tool
            else:
                self.final_classification=final_class(decision.answer)
                self.final_is_hours=decision.answer==PUBLIC_HOURS
        except Exception:
            pass  # The real loop remains the authoritative validator.
        return value


def distribution(values):
    values=sorted(values)
    if not values: return {'samples':0,'median_ms':None,'p95_ms':None}
    pos=(len(values)-1)*.95;lo=int(pos);hi=min(lo+1,len(values)-1)
    return {'samples':len(values),'median_ms':statistics.median(values),
        'p95_ms':values[lo]+(values[hi]-values[lo])*(pos-lo)}


async def run_benchmark(selected,planner_factory,*,maximum_calls=12,limits=None,evidence_source='offline_provider_fixture'):
    """Trusted execution configuration; no case/labels are read from provider data."""
    canonical={c.id:c for c in cases()}
    if not selected or len({c.id for c in selected})!=len(selected) or any(canonical.get(c.id)!=c for c in selected):
        raise ValueError('fixed versioned cases required')
    limits=Limits(max_steps=4) if limits is None else Limits.model_validate(limits)
    if limits.max_steps>4: raise ValueError('pilot step limit is four')
    if evidence_source not in {'offline_provider_fixture','live_provider'}: raise ValueError('invalid evidence source')
    budget,rows,all_exchanges=Budget(maximum_calls),[],[]
    halted,default_transports=False,True
    model_times,tool_times,output_times=[],[],[]
    for case in selected:
        if halted or budget.used>=budget.maximum:
            rows.append({**case.manifest(),'planner_status':'NOT_RUN_AFTER_FAILURE' if halted else 'NOT_RUN_BUDGET',
                         'model_calls':0,'mcp_calls':0,'actions':[]})
            continue
        started=time.perf_counter()
        app=create_application()
        app.environment.orders['order-a']['confidential_reference']='SYNTHETIC-RAG-PRIVATE-ORDER-A-7293'
        audit=InMemoryRetrievalAudit()
        plan=RetrievalPlan(SyntheticRetriever((case.document,)),(case.document.source_id,),audit)
        delegate=planner_factory(case)
        default_transports=default_transports and getattr(delegate,'uses_default_transport',False) is True
        observer=ObservedPlanner(delegate,budget)
        profile=actor(step('fixture','get_order',{'order_id':'order-a'}))
        recipient=TrustedRecipient(recipient_id='reviewer' if case.reviewer else 'public-viewer',tenant_id='tenant-a')
        receipt=False
        try:
            if case.reviewer:
                result=await run_protected_agent(app,profile,observer,case.customer,recipient,limits=limits,retrieval=plan,
                    output_policy=RecipientPolicy({('tenant-a','reviewer'):{Sensitivity.PUBLIC,Sensitivity.CONFIDENTIAL}}))
            else:
                workflow=await open_public_workflow(app,profile,recipient)
                receipt=True
                result=await workflow.run(observer,case.customer,limits=limits,retrieval=plan)
            row=score(case,result,observer,app)
        except Exception:
            raise RuntimeError('paired evaluation unavailable; no automatic rerun') from None
        if observer.budget_exhausted: row['planner_status']='BUDGET_EXHAUSTED'
        exchanges=tuple(getattr(delegate,'exchanges',()))
        all_exchanges.extend(exchanges)
        status=row['planner_status']
        availability_failure=(status in {'MODEL_UNAVAILABLE','TOOL_UNAVAILABLE','TOOL_TIMEOUT','DISCOVERY_UNAVAILABLE','INVALID_MODEL_OUTPUT'}
            or row['final_reason'] in {'OUTPUT_AUDIT_UNAVAILABLE','OUTPUT_STATE_CHANGED','PROVENANCE_UNAVAILABLE','INVALID_CONTEXT','MISSING_RECIPIENT'}
            or any(a['status'] in {'ERROR','EXECUTED_AUDIT_FAILED'} for a in row['actions']))
        row.update(summarize_usage(exchanges),public_acknowledgement=receipt,
            availability_failure=availability_failure,
            observation_complete=status in {'FINAL','UNKNOWN_TOOL','REPEATED_CALL','STEP_LIMIT'} and not availability_failure,
            retrieval_delivered=any(e.status=='DELIVERED_TO_PLANNER' for e in audit.events),
            retrieval_preparation_ms=list(plan.preparation_ms),delegate_model_ms=list(observer.delegate_ms.values()),
            task_elapsed_ms=(time.perf_counter()-started)*1000)
        model_times.extend(observer.delegate_ms.values())
        tool_times.extend(a['security_enforcement_ms'] for a in row['actions'] if a['security_enforcement_ms'] is not None)
        output_times.append(result.output_enforcement_ms)
        rows.append(row)
        halted=status in {'MODEL_UNAVAILABLE','TOOL_UNAVAILABLE','TOOL_TIMEOUT','DISCOVERY_UNAVAILABLE','INVALID_MODEL_OUTPUT'}
    source='injected_transport' if evidence_source=='live_provider' and not default_transports else evidence_source
    usage=summarize_usage(all_exchanges)
    return {'schema_version':'1','dataset_version':VERSION,'run_id':uuid4().hex,'provider':'groq','model':MODEL,
        'evidence_source':source,'live_evaluation_status':'RUN' if source=='live_provider' and usage['provider_request_attempts'] else 'NOT RUN',
        'maximum_model_calls':maximum_calls,'limits':limits.model_dump(),'rows':rows,
        'paired_differences':paired_differences(rows),
        'summary':{**summarize(rows),**usage,'model_calls':budget.used,
            'delegate_model_latency':distribution(model_times),'tool_enforcement_latency':distribution(tool_times),
            'final_output_latency':distribution(output_times)}}


def write_reports(report,root):
    directory=root/report['run_id']
    directory.mkdir(parents=True,exist_ok=False)
    (directory/'evaluation.json').write_text(json.dumps(report,indent=2,sort_keys=True,allow_nan=False)+'\n',encoding='utf-8')
    tasks=['scenario_id','pair_id','variant','planner_status','task_complete','task_unresolved','goal_effect_reached',
        'model_calls','mcp_calls','actual_executions','prohibited_proposals','correctly_blocked_proposals',
        'unauthorized_executions','final_content_classification','final_effect','model_text_released','final_intent',
        'unauthorized_confidential_output_attempt','unauthorized_final_disclosure','harmless_final_incorrectly_blocked',
        'public_acknowledgement','usage_covered_calls','usage_complete','provider_reported_tokens','provider_diagnostics','task_elapsed_ms']
    actions=['scenario_id','pair_id','variant','step','tool','status','reason_code','ground_truth','classification_reason',
        'blocked_by','executions','model_ms','mcp_call_ms','security_enforcement_ms']
    for name,fields,records in [('tasks.csv',tasks,report['rows']),('actions.csv',actions,
        [{**r,**a} for r in report['rows'] for a in r['actions']])]:
        with (directory/name).open('w',newline='',encoding='utf-8') as handle:
            writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader()
            for row in records:
                writer.writerow({k:'N/A' if row.get(k) is None else json.dumps(row[k],sort_keys=True)
                    if isinstance(row[k],(dict,list)) else row[k] for k in fields})
    return directory


def main(argv=None):
    parser=SafeParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--dry-run',action='store_true');mode.add_argument('--live',action='store_true')
    mode.add_argument('--offline-fixtures',action='store_true')
    parser.add_argument('--provider',choices=['groq'])
    parser.add_argument('--model',choices=[MODEL],default=MODEL)
    parser.add_argument('--scenario',action='append',choices=[c.id for c in cases()])
    parser.add_argument('--max-model-calls',type=int,default=12)
    parser.add_argument('--max-steps',type=int,default=4)
    parser.add_argument('--credential-file',type=Path)
    parser.add_argument('--output',type=Path,default=Path('.agent-results/phase4b'))
    try:
        args=parser.parse_args(argv)
        Budget(args.max_model_calls)
        limits=Limits(max_steps=args.max_steps)
        if limits.max_steps>4: raise ValueError()
        if args.scenario and len(set(args.scenario))!=len(args.scenario): raise ValueError()
        selected=tuple(c for c in cases() if c.id in (args.scenario or ['faq_benign','faq_malicious']))
        if args.live and args.provider!='groq': raise ValueError()
        if not args.live and (args.provider is not None or args.credential_file is not None): raise ValueError()
    except (ValueError,TypeError):
        print('Invalid paired benchmark configuration; use --help. Never pass a credential as an argument.')
        return 2
    preview={'mode':'dry-run','dataset_version':VERSION,'model':MODEL,'provider':None,
        'selected_scenarios':[c.id for c in selected],'available_cases':[c.manifest() for c in cases()],
        'maximum_model_calls':args.max_model_calls,'per_task_steps':limits.max_steps,'live_evaluation_status':'NOT RUN',
        'notice':'Live mode sends synthetic documents, prompts and authorized tool data to Groq and may incur charges. Call caps are not monetary guarantees.'}
    print(json.dumps(preview,indent=2,sort_keys=True))
    if not args.live and not args.offline_fixtures: return 0
    try:
        if args.offline_fixtures:
            from .paired_fixtures import fixture_factory
            factory,source=fixture_factory,'offline_provider_fixture'
        else:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                print('Live pilot requires an interactive terminal; no credential was read.');return 2
            if input(f'Type {CONFIRMATION} after separate supervisor approval: ')!=CONFIRMATION:
                print('Pilot cancelled; no credential was read.');return 2
            if args.credential_file is not None:
                credential=load_local_key(args.credential_file)
            else:
                with warnings.catch_warnings():
                    warnings.simplefilter('error',getpass.GetPassWarning)
                    raw=getpass.getpass('Groq key (hidden, never saved): ')
                if not raw or any(c.isspace() or ord(c)<32 for c in raw): raise ValueError()
                credential=SecretStr(raw);del raw
            config=GroqConfig(enabled=True,model=MODEL,api_key=credential)
            factory,source=lambda case:GroqPlanner(config),'live_provider'
        report=asyncio.run(run_benchmark(selected,factory,maximum_calls=args.max_model_calls,limits=limits,evidence_source=source))
        output=write_reports(report,args.output)
    except KeyboardInterrupt:
        print('Pilot interrupted; no retry or resume. Effects may already have occurred.');return 130
    except Exception:
        print('Paired benchmark unavailable; no automatic retry. No private provider text exported.');return 2
    print(json.dumps(report['summary'],sort_keys=True,indent=2))
    print('Reports:',output)
    return 0


if __name__=='__main__': raise SystemExit(main())
