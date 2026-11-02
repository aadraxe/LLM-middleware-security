"""Synthetic in-memory support tools only: no email/payment/database/network I/O."""
from collections import Counter

from .registry import support_registry
from .schemas import EmailArguments, OrderArguments, RefundArguments, ResourceInfo


class FakeSupportEnvironment:
    def __init__(self):
        self.calls = Counter()
        self.arguments: list[tuple[str, dict]] = []
        self.orders = {
            "order-a": {"order_id": "order-a", "tenant_id": "tenant-a", "status": "paid"},
            "order-b": {"order_id": "order-b", "tenant_id": "tenant-b", "status": "paid"},
        }

    def _record(self, name, args):
        self.calls[name] += 1
        self.arguments.append((name, args.model_dump()))

    def get_order(self, args: OrderArguments):
        self._record("get_order", args)
        return dict(self.orders[args.order_id])

    def send_email(self, args: EmailArguments):
        self._record("send_email", args)
        return {"sent": True}

    def issue_refund(self, args: RefundArguments):
        self._record("issue_refund", args)
        return {"refunded": True, "amount_cents": args.amount_cents}

    def registry(self):
        return support_registry(get_order=self.get_order, send_email=self.send_email,
                                issue_refund=self.issue_refund,
                                resources=tuple(ResourceInfo(resource_id=o["order_id"], tenant_id=o["tenant_id"])
                                                for o in self.orders.values()))
