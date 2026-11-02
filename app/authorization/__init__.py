"""Internal deterministic tool authorization; no transport or identity provider.

Only trusted application code constructs context, registry, policy and executor.
Agent input is limited to ToolInvocation. No API route imports this package.
"""
