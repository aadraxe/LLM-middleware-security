AegisFlow: project summary

AegisFlow is a research prototype that controls what an AI agent is allowed to do when it reads untrusted text and can call tools. It started as a prompt filter with a fine-tuned DistilBERT classifier. That classifier scored F1 0.939 on its own test set but caught only 21.8% of attacks on an unfamiliar benchmark (real measurement). So the project moved to deterministic controls: every tool call is authorized by host-owned policy, confidential data is tracked per session, and final answers are checked before release.

Key results:
- In a 12-scenario ablation, prohibited operations executed: 7/7 with no checks, 2/7 with authorization only, 0/7 with authorization plus provenance. The cost was 1 of 5 legitimate tasks blocked (scripted test scenario).
- In a 23-scenario RAG suite with 15 injection cases, 12/12 prohibited tool attempts were blocked with 0 unauthorized executions (scripted test scenario).
- In a live gpt-oss-120b run, the model proposed 2 prohibited actions and both were blocked. The run stopped early at a rate limit (live model run).

Status: synthetic tools, simulated identities and in-memory state; not deployed. Next: AgentDojo evaluation, AWS deployment and less overblocking.

Repository: [REPO LINK]
