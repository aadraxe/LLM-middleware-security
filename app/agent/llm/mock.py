"""Deterministic native structured decisions; no free-text action parser."""
from .contracts import Decision, ToolCall


class MockPlanner:
    def __init__(self, *responses):
        self._responses, self._position = responses, 0

    async def propose(self, request):
        if self._position >= len(self._responses):
            raise ValueError("mock responses exhausted")
        response = self._responses[self._position]
        self._position += 1
        return response(request) if callable(response) else response


def call(name, arguments, *, call_id="mock-call"):
    from app.authorization.schemas import canonical_json
    return Decision(kind="tool", tool=ToolCall(call_id=call_id, name=name, arguments_json=canonical_json(arguments)))


def final(text="The synthetic task is complete."):
    return Decision(kind="final", answer=text)
