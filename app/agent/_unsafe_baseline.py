"""UNSAFE TEST-ONLY experiment. Never imported by default application composition.

No listener, real credentials, remote tools or real effects. This deliberately
omits roles, tenant ownership, recipients, refund approval and information flow.
Registry/schema validation and required authorization audits still apply.
"""
from uuid import uuid4
from app.authorization.schemas import AuthorizationDecision, request_digest
from .composition import create_authorization_only_application


class _UnsafeTestPolicy:
    async def evaluate(self, request):
        return AuthorizationDecision(decision_id=uuid4(), effect="ALLOW", reason_code="AUTHORIZED",
            policy_version="v1", request_digest=request_digest(request))


def create_unsafe_synthetic_test_application():
    application = create_authorization_only_application()
    application._policy = _UnsafeTestPolicy()
    return application
