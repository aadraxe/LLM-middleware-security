"""Explicit supervisor-approved local evaluation; never imported by default CLI.

Credential files are trusted local input, not model input. This entry point is
for an already approved synthetic experiment, not an authentication endpoint.
"""
import asyncio
import io
import json
from pathlib import Path

from dotenv.parser import parse_stream
from pydantic import SecretStr

from .contracts import Limits
from .groq import GroqConfig, GroqPlanner
from .live import SafeParser, run_evaluation, write_reports
from .live_scenarios import MODEL, scenarios


def load_local_key(path: Path) -> SecretStr:
    """Read only the named key; no env mutation, interpolation, discovery or echo."""
    try:
        with path.open("rb") as handle:
            data = handle.read(65537)
        if len(data) > 65536:
            raise ValueError()
        matches = []
        for binding in parse_stream(io.StringIO(data.decode("utf-8-sig"))):
            if binding.error:
                raise ValueError()
            if binding.key == "GROQ_API_KEY":
                matches.append(binding.value)
        if len(matches) != 1:
            raise ValueError()
        value = matches[0]
        if (not value or "${" in value or any(ord(c) < 33 or ord(c) > 126 for c in value)):
            raise ValueError()
        return SecretStr(value)
    except Exception:
        raise RuntimeError("local Groq credential unavailable") from None


class UsageGuard:
    """Additional trusted stop guard; provider counts are observations, not billing."""
    def __init__(self):
        self.total = 0
        self.stopped = False

    def check(self, exchange):
        usage = exchange.usage
        if usage is None:
            self.stopped = True
        else:
            self.total += usage.total_tokens
            self.stopped = (usage.prompt_tokens > 32768 or usage.completion_tokens > 1024 or self.total > 100000)
        if self.stopped:
            raise RuntimeError("provider usage stop")


class GuardedPlanner:
    def __init__(self, delegate, guard):
        self.delegate, self.guard = delegate, guard

    @property
    def exchanges(self): return self.delegate.exchanges

    @property
    def uses_default_transport(self): return self.delegate.uses_default_transport

    async def propose(self, request):
        if self.guard.stopped:
            raise RuntimeError("provider usage stop")
        decision = await self.delegate.propose(request)
        self.guard.check(self.delegate.exchanges[-1])
        return decision


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("--approved-live", action="store_true")
    parser.add_argument("--credential-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".agent-results/live-approved"))
    try:
        args = parser.parse_args(argv)
        if not args.approved_live:
            raise ValueError()
        config = GroqConfig(enabled=True, model=MODEL, api_key=load_local_key(args.credential_file))
        guard = UsageGuard()
        report = asyncio.run(run_evaluation(scenarios(), Limits(max_steps=4), 40,
            lambda: GuardedPlanner(GroqPlanner(config), guard), evidence_source="live_provider"))
        report["experiment"] = {"maximum_calls": 40, "maximum_steps_per_scenario": 4,
            "usage_stop": guard.stopped, "usage_limits": {"prompt_tokens_per_call": 32768,
                "completion_tokens_per_call": 1024, "total_tokens": 100000},
            "credential_source": "explicit_local_file", "automatic_retries": False}
        output = write_reports(report, args.output)
    except KeyboardInterrupt:
        print("Evaluation interrupted; no automatic rerun.")
        return 130
    except Exception:
        print("Authorized evaluation unavailable; no automatic rerun. No secret or provider text exported.")
        return 2
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    print("Reports:", output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
