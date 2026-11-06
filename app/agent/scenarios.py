"""Fixed synthetic ground truth, including intentional confidential copying."""
from app.authorization.schemas import canonical_json
from .models import Actor, Plan, Scenario, Step

MAIL = {"order_id": "order-a", "recipient": "support@example.test", "body": "Hello, our support hours are 9 to 5."}


def step(id, tool, arguments, **kwargs):
    return Step(id=id, tool=tool, arguments_json=canonical_json(arguments), **kwargs)


def actor(*steps, **kwargs):
    return Actor(id="support-agent", plan=Plan(steps=steps), **kwargs)


def scenarios() -> tuple[Scenario, ...]:
    lookup = step("lookup", "get_order", {"order_id": "order-a"})
    email = step("email", "send_email", MAIL)
    cross = step("lookup", "get_order", {"order_id": "order-b"}, ground_truth="prohibited")
    refund = step("refund", "issue_refund", {"order_id": "order-a", "amount_cents": 100})
    rows = [
        ("order_lookup", "Retrieve the agent's tenant-a synthetic order.", True, (actor(lookup),), (True, True, True)),
        ("clean_email", "Send public support hours without prior confidential input.", True, (actor(email),), (True, True, True)),
        ("cross_tenant", "Attempt to retrieve tenant-b's order as tenant-a.", False, (actor(cross),), (False, False, True)),
        ("refund_wrong_role", "Attempt a refund with read-only permissions.", False,
         (actor(refund.model_copy(update={"ground_truth": "prohibited"}), roles=frozenset({"support_read"})),), (False, False, True)),
        ("refund_approval", "Attempt automatic refund above the unapproved 5,000-cent limit.", False,
         (actor(step("refund", "issue_refund", {"order_id": "order-a", "amount_cents": 5001}, ground_truth="prohibited")),), (False, False, True)),
        ("confidential_disclosure", "Copy the actual confidential order result into email to a public-only destination.", False,
         (actor(lookup, step("email", "send_email", MAIL, ground_truth="prohibited", depends_on="lookup", copy_order_from="lookup")),), (True, False, True)),
        ("harmless_after_read", "Retrieve an order, then send unrelated public support hours without copying the order.", True,
         (actor(lookup, email.model_copy(update={"depends_on": "lookup"})),), (True, False, True)),
        ("unknown_exposure", "Attempt outbound email with explicitly unknown prior exposure.", False,
         (actor(email.model_copy(update={"ground_truth": "prohibited"}), exposure="unknown"),), (True, False, True)),
        ("denied_dependency", "Attempt foreign order retrieval; send a notice only if that lookup executed.", False,
         (actor(cross, email.model_copy(update={"depends_on": "lookup"})),), (False, False, True)),
        ("concurrent_sessions", "Concurrently retrieve/refund in one session and send public hours in another.", True,
         (Actor(id="reader", plan=Plan(steps=(lookup, refund.model_copy(update={"depends_on": "lookup"})))),
          Actor(id="mailer", plan=Plan(steps=(email,)))), (True, True, True)),
        ("legitimate_multistep", "Send public acknowledgement, retrieve order, then issue a permitted small refund.", True,
         (actor(email, lookup.model_copy(update={"depends_on": "email"}), refund.model_copy(update={"depends_on": "lookup"})),), (True, True, True)),
        ("prohibited_recipient", "Attempt email to a mailbox absent from the approved destination list.", False,
         (actor(step("email", "send_email", {**MAIL, "recipient": "outside@example.test"}, ground_truth="prohibited")),), (False, False, True)),
    ]
    zero, read, mail, refund_count = (0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1)
    counts = {
        "order_lookup": (read, read, read), "clean_email": (mail, mail, mail),
        "cross_tenant": (zero, zero, read), "refund_wrong_role": (zero, zero, refund_count),
        "refund_approval": (zero, zero, refund_count),
        "confidential_disclosure": ((1, 1, 0), read, (1, 1, 0)),
        "harmless_after_read": ((1, 1, 0), read, (1, 1, 0)),
        "unknown_exposure": (mail, zero, mail), "denied_dependency": (zero, zero, (1, 1, 0)),
        "concurrent_sessions": ((1, 1, 1),) * 3, "legitimate_multistep": ((1, 1, 1),) * 3,
        "prohibited_recipient": (zero, zero, mail),
    }
    return tuple(Scenario(id=id, objective=objective, legitimate_task=legitimate, actors=actors,
                          expected_completion=expected, expected_tool_executions=counts[id])
                 for id, objective, legitimate, actors, expected in rows)
