# Research record

Checked on **2026-10-31**. Everything below came from the linked source on that date, unless it is
marked **unverified** or **inferred**. No AWS credentials were available, so nothing here has been
confirmed against a live AWS account. D12 in [STAGES.md](STAGES.md) closes that gap.

Sources are referenced as `[S1]`, `[S2]` and so on. The list is at the end.

## 1. Strands Agents

The latest Python release we could confirm is **1.63.0**, the version the PoC has installed, requiring Python `>=3.10`, with `otel` and `a2a` extras [S1].
`poc-strands-orchestrator` pins `strands-agents[otel]~=1.63` and `bedrock-agentcore~=1.25`.

| Option | Who decides what runs | Cycles | Parallel | Fit for this product |
|---|---|---|---|---|
| Agents-as-tools | The orchestrator LLM, at run time | Through its own loop | Yes, tool calls in one response run together with `ConcurrentToolExecutor` (PoC) | **Inside a stage** |
| Graph | Developer-defined edges, with an LLM decision at nodes | Yes | Along edges | Possible engine, rejected ([ADR-0001](adr/0001-deterministic-engine-with-strands-stage-orchestrators.md)) |
| Swarm | Agents hand off to each other | Yes, bounded by timeouts and handoff limits | One active agent at a time | Not used: no coordinator to hold a gate |
| Workflow | A fixed task DAG | No | Yes | Too rigid: no loops, and a failed task halts its dependents |

Sources: [S2], [S3], `poc-strands-orchestrator/README.md`.

**Interrupts** [S4]:

- An interrupt pauses the agent loop. It can be raised from a hook (`BeforeToolCallEvent`,
  `BeforeToolsEvent`) or from a tool (`tool_context.interrupt`).
- The agent returns `stop_reason == "interrupt"` and `result.interrupts`. You resume by calling it
  with `interruptResponse` blocks.
- Interrupts also work in Swarm and Graph, raised from `BeforeNodeCallEvent` or from inside a node.
- A session manager is what lets a run resume after a teardown.
- The docs warn that **"Session state is trusted input, so do not load sessions from untrusted
  sources"**, and give session files inside a cloned repository as the example [S5].

**Session persistence** [S6]:

- `FileSessionManager` and `S3SessionManager` store messages and agent metadata.
  `SnapshotSessionManager` is recommended for new single-agent sessions.
- File and S3 remain the path for Graph and Swarm.
- Python multi-agent session managers track orchestration state, not each agent's conversation.
- Session managers **are not thread-safe and take no distributed lock**.

**OpenTelemetry:** Strands emits spans for agents, model calls and tools, and worker spans nest inside
the orchestrator's trace. This is from `poc-strands-orchestrator/README.md` and `telemetry.py` plus
[S7]. The current Strands traces doc page was not retrievable (404), so span attribute names are
**unverified** until issue D5-11.

**Behaviours the PoC found that affect this design** (`poc-strands-orchestrator/README.md`,
`llm/bedrock.py`):

- A cancelled agent clears its cancel signal, so the Bedrock reader thread keeps generating and
  billing. `AbortableBedrockModel` works around this.
- Turn and token limits are shared across workers.
- Tool results arrive only when the whole parallel batch is done, so a worker's finish must be read
  from its own stream.
- A refusal looks like a successful tool call, so the stop reason must be inspected.

## 2. Bedrock AgentCore: availability

| Capability | Status on 2026-10-31 | Evidence |
|---|---|---|
| Platform | GA since October 2025, in nine Regions at launch | [S8] |
| Runtime, Gateway, Identity, Code Interpreter, Browser, Observability | GA | [S8] (the April 2026 note names them as GA in São Paulo) |
| Memory | GA, **inferred**: no separate GA note, and no preview label in the notes or FAQ | [S8], [S9] |
| Policy | GA, across 13 Regions (March 2026 section) | [S8] |
| Evaluations | GA (March 2026) | [S8] |
| Harness | **GA per release notes (July 2026 section); the FAQ still says preview.** We trust the release notes | [S8], [S9], [S10] |
| Agent Registry | GA (August 2026) | [S8] |
| Runtime managed session storage | **Preview.** Maximum 1 GB per session, 14 days idle retention, and a runtime version update resets it | [S11], [S12] |
| Failure insights | Preview | [S8] |
| Instances compute type | Released August 2026, with sessions up to 14 days on your own EC2 | [S8], [S13] |
| CDK L2 constructs | **Stable in `aws-cdk-lib` since v2.255.0; the Policy submodule is still alpha** | [S8] |

**Design rule:** nothing critical depends on a preview feature. Session storage is optional
([ADR-0004](adr/0004-agentcore-runtime-custom-strands-container.md)).

### Limits that shaped the design

| Limit | Value | Adjustable | Consequence |
|---|---|---|---|
| Runtime idle timeout | 15 minutes by default | Yes | A session cannot simply wait for a human |
| Runtime max lifetime | 8 hours on microVM, 14 days on Instances | Up to those ceilings | **No session can hold a gate that lasts weeks** |
| Synchronous request | 15 minutes | No | Agent work is invoked asynchronously |
| Streaming duration | 60 minutes | No | Progress does not depend on an open stream |
| Asynchronous job | 8 hours | No | Bounds one step |
| Session vCPU and memory | 2 vCPU, 8 GB | No | Sizing limit for team toolchains |
| Docker image | 2 GB | No | Sizing limit for team sandbox images |
| New sessions | 25 TPS | Yes | Dispatch is queued |
| Active sessions | 5,000 in us-east-1 and us-west-2, 2,500 elsewhere | Yes | Team concurrency caps |
| `InvokeAgentRuntimeCommand` | Command up to 64 KB, output up to 100 MB, timeout 1 to 3600 seconds | No | Workspace exec tool |
| Gateway tool calls | 200 TPS, 15 minute timeout, 6 MB payload | Yes | Tool design |
| Code Interpreter | 2 vCPU, 8 GB, 10 GB disk, 8 hour async | No | QA scripts |
| Browser | 1 vCPU, 4 GB, 10 GB disk, default session 15 minutes, maximum 8 hours, live view, recording on custom browsers | Mixed | QA evidence |
| Memory events | 7 to 365 days expiry | No | Not the audit store |

Sources: [S14], [S15], [S16], [S17], [S18].

### Other relevant facts

- **Billing:** microVM CPU is not billed during I/O wait, but memory is billed while the session runs
  [S9], [S19]. A waiting session still costs money, which is another reason to hold no session during
  a gate.
- **Session isolation:** each session has its own microVM. Session context keys (V2 platform,
  October 2026) add `runtimeSessionId` and `runtimeArn` to the vended credentials, so a single role
  can restrict each session to its own data [S8], [S15]. AgentCore does not map sessions to users, so
  the backend must do that [S15].
- **Commands and images:** commands run in the same container as the agent code and have full access inside the VM, including its credentials, and the input command is logged to CloudWatch [S61]. An image belongs to a Runtime, and team images must be ARM64 and meet the service contract, so each image needs a provisioned Runtime.
- **Session traps:** session context keys "do not prove that a request was made from inside the corresponding microVM", SDK clients created at module scope lack them, and a stopped session returns to Active on its next invocation with new compute [S15].
- **Policy principals** are an IAM entity or an OAuth user with JWT claims, so a single execution role cannot say which stage is calling [S64].
- **Network:** security groups do not filter traffic to Amazon DNS [S65]. Code Interpreter has Sandbox, Public and VPC modes [S71]. Browser supports managed Chromium policies [S70].
- **Identity:** built-in providers include GitHub, Atlassian, Slack and Microsoft [S20]. The documented
  GitHub setup is an **OAuth App user flow** [S21]. Nothing in the docs we read covers GitHub App
  installation tokens, so we broker those ourselves
  ([ADR-0010](adr/0010-autonomous-merge-github-app.md)). A hosted Consent Portal was added in
  September 2026 [S8].
- **Gateway:** turns OpenAPI, Smithy and Lambda into MCP tools, has inbound and outbound auth, and has
  configurable rate limits per caller, target or tool (August 2026) [S8], [S22].
- **Policy:** Cedar policies evaluated at the Gateway boundary, outside agent code [S23].
- **Step Functions harness integration:** Request Response only, with a **15 minute** limit, and
  "Stopping an execution or the Task state does not stop the harness" [S24]. This is one reason we run
  our own container.
- **A coding-agent post on AWS's blog** describes running git with a narrow credential and notes that
  the GitHub MCP server cannot clone private repositories [S25].

## 3. Bedrock model IDs

Verified from the Bedrock model cards, **not** by invoking anything [S26], [S27], [S28], [S29]. The
AWS CLI session on this machine had expired, and D12 includes a live check.

| Model | Base ID | Geo profiles | Global profile | Launch | EOL not before | Notable limits |
|---|---|---|---|---|---|---|
| Opus 5.5 | `anthropic.claude-opus-5-5` | `us.`, `eu.`, `au.`, `jp.` | `global.anthropic.claude-opus-5-5` | 2026-09-22 | 2027-09-22 | Adaptive thinking always on. `tool_choice` `auto` and `none` only. In-Region only in eu-west-2 |
| Sonnet 5.5 | `anthropic.claude-sonnet-5-5` | `us.`, `eu.`, `au.` | `global.anthropic.claude-sonnet-5-5` | 2026-09-28 | 2027-09-28 | `tool_choice` `auto` and `none` only |
| Haiku 5.5 | `anthropic.claude-haiku-5-5` | `us.`, `ca.`, `eu.`, `au.`, `jp.` | `global.anthropic.claude-haiku-5-5` | 2026-10-07 | 2027-10-07 | Higher rates above 100,000 prompt tokens |
| Fable 5.1 | `anthropic.claude-fable-5-1` | `us.` | `global.anthropic.claude-fable-5-1` | 2026-09-01 | 2027-09-01 | Catalog entry only, not a default |

All three 5.5 models have a 1M token context and 128K max output, support explicit prompt caching
(minimum 512 tokens per checkpoint, 4 checkpoints, 5 minute or 1 hour TTL), Guardrails, application
inference profiles and structured outputs on `bedrock-runtime`.

**Not supported on `bedrock-runtime`:** count tokens and implicit caching. Service tiers: Standard
only. There is no batch.

**Routing notes:**

- Destination Regions depend on the source Region. The cards list them, and `GetInferenceProfile`
  gives the current routing.
- Some profiles carry a "limited model selection" designation: Canada geo, and In-Region in Seoul,
  Singapore, London, Zurich and São Paulo [S30]. A successor model may not arrive on those profiles.
- These models are sold through AWS Marketplace. PoC READMEs record the first-time-use form and
  one-time subscribing invocation, which the deployed role deliberately cannot perform.

**Application inference profiles** can wrap a system profile and carry tags for cost allocation [S31].
We use one per team and model.

## 4. Durable long-running work on AWS

| Requirement | Step Functions Standard | AgentCore session | DynamoDB alone |
|---|---|---|---|
| Wait for days or weeks | Up to 1 year [S32] | 8 hours, or 14 days on Instances [S14] | Unlimited, but needs its own timers |
| Cost while waiting | Per transition, nothing while idle | Memory billed, or lost at timeout | Nothing |
| Per-execution visibility and stop | Built in, with `StopExecution` | No workflow view | Must be built |
| Retry and timeout semantics | Built in, declarative | Must be built | Must be built |
| Atomic gate decision with audit | No, needs a store beside it | No | **Yes, with transactions and conditions** |
| Offline testability of logic | Poor for logic held in ASL | Poor | Excellent |

Key facts [S32], [S33], [S34], [S35]:

- `.waitForTaskToken` pauses until `SendTaskSuccess` or `SendTaskFailure`.
- A token is at most 2048 characters. Output is at most 256 KiB.
- `TaskTimedOut` means the token expired **or the task is already closed**.
- History is capped at **25,000 events**, after which the execution fails. AWS's advice is to start a
  new execution.
- Executions are capped at 1 year, and history is retained for 90 days after close.
- `CreateStateMachine` refills at 1 per second.
- Stopping an execution does not necessarily cancel the work it started.

**Decision:** a single interpreter state machine as the durable driver, with DynamoDB as the authority
for run and gate state ([ADR-0002](adr/0002-durable-execution-step-functions-dynamodb.md)).

A related note: Gateway now has a Step Functions connector that exposes task-token operations as MCP
tools [S8]. **We deliberately do not give agents those tools**: an agent able to complete a task token
could complete a gate.

## 5. Integrations

### GitHub

- Check run writes are **only available to GitHub Apps** [S36].
- Installation tokens expire after one hour and can be narrowed to specific repositories and
  permissions. Creating one requires a JWT [S37].
- Tarball links for private repositories expire after five minutes [S38].
- Webhooks: `X-Hub-Signature-256` is HMAC-SHA256 and must be compared in constant time [S39]. Respond
  within 10 seconds. `X-GitHub-Delivery` is unique per event and retained on redelivery, and the docs
  read as though redelivery is manual, so we reconcile on a schedule [S40].
- **The async merge API is GA and recommended,** and it can add to a merge queue. The sync endpoint "does not support ... merging with a merge queue". An `enqueued` result is final for that request and does not mean merged [S60].
- `update-branch` returns 202 with no SHA, while `POST /merges` returns the commit, and takes only `base`, `head` and `commit_message` [S62]. `merge-upstream` syncs a fork branch [S62]. D4-12 keeps tests on these.
- An App installation token triggers `push` and `pull_request` workflows, unlike `GITHUB_TOKEN` [S75]. Running untrusted code under `pull_request_target` can grant "unintended access to write privileges or secrets" [S75]. `default_workflow_permissions` is readable through the API [S76].
- A workflow dispatch can return a run ID with `return_run_details`, but only in the response, which a crash loses [S63].
- A check attaches to a commit, and neutral counts as passing [S59].
- Forks: on public repos, by default "all first-time contributors require approval to run workflows", and on private repos, an org disabling fork workflows cannot be overridden per repo [S69].
- Required checks can be pinned to a specific app with `app_id` [S41]. Rulesets can let a GitHub App
  bypass rules, and bypass lists need an organization-owned repository [S42].
- Merge queues need `merge_group` triggers or required checks never report, and are available only in organization-owned public repos, or private repos under Enterprise Cloud [S43]. A workflow skipped by a path
  or branch filter can leave a required check pending and block merging, so required workflows should not be
  skippable [S59].
- The merge endpoint takes `sha`, the "SHA that pull request head must match to allow merge". It returns 409 if the head
  differs and 405 if the merge cannot be performed [S44]. That guards against merging a different head, but says nothing about
  the base, so the merge guard adds an up-to-date check ([ADR-0010](adr/0010-autonomous-merge-github-app.md)).

### Jira Cloud

- REST-registered webhooks **expire after 30 days** unless refreshed. There is a limit of 5 per OAuth
  2.0 app, per user, per tenant.
- Admin webhooks can carry an HMAC `X-Hub-Signature`. OAuth 2.0 webhooks carry a bearer token.
- Failed deliveries retry up to five times. `X-Atlassian-Webhook-Identifier` stays the same across
  retries.
- **No ordering guarantee is documented.** Concurrency is capped per tenant and host [S45].
- Transition IDs differ per workflow, so the adapter calls Get Transitions and resolves by status. Use
  `transitions.fields` to find required fields [S46].

### Slack

- Signature: `v0:<timestamp>:<raw body>` with HMAC-SHA256, in `X-Slack-Signature`. Reject timestamps
  older than 5 minutes [S47].
- Interactive payloads need a 200 within **3 seconds**. `trigger_id` expires in 3 seconds and is
  single use. `response_url` allows 5 uses in 30 minutes [S48].

### Linear and Azure DevOps

- Linear: `Linear-Signature` HMAC over the raw body, `webhookTimestamp` within a minute,
  `Linear-Delivery` UUID, 5 second response, retries at 1 minute, 1 hour and 6 hours [S49].
- Azure DevOps service hooks use HTTPS, with basic auth documented [S50]. We read no HMAC signing in
  that page, so the adapter uses a shared secret header over TLS and re-fetches the resource.

## 6. Identity and web hosting

- Cognito user pools federate OIDC and SAML, map IdP claims to pool attributes, and can override
  groups in tokens with a pre token generation trigger using `groupOverrideDetails` [S51], [S52],
  [S53], [S54].
- Cognito "doesn't remove attributes from users when the source attribute is no longer sent", and a value over the 2,048 character limit makes sign-in fail [S66]. Federated sign-ins invoke Pre authentication on later sign-ins, and an Inbound federation trigger exists [S67]. `prompt=login` and `max_age` are supported on managed login [S68].
- **Unverified, to prove in D12-10:** whether a federated user can overwrite a mapped attribute, and how large group lists behave at real IdPs ([ADR-0008](adr/0008-sso-cognito-as-federation-broker.md)).
- CloudFront removes `Authorization` from GET and HEAD requests before forwarding, unless configured
  to forward it [S55].
- Lambda function URLs with origin access control need `x-amz-content-sha256` on POST and PUT, computed
  by the caller [S56]. Browsers expose `crypto.subtle` only in secure contexts (PoC `web/src/lib/api.ts`).
- EventBridge Scheduler supports one-time schedules [S57].
- AppSync Events gives managed WebSocket channels and HTTP publish [S58].

## 7. What the PoCs taught us

| Lesson (source) | Verified where | Design response | Proved by |
|---|---|---|---|
| A failed audit write let an old approval override a later rejection, because LangGraph replays a saved resume value | README, `test_audit_failure_on_approve_cannot_write_after_a_later_rejection` | Decision, audit and outbox commit in one transaction. No framework replay holds a decision | G3, G6 |
| "A saved decision stands": a later reject cannot overrule | LangGraph README, Limitations | Reject vetoes while a gate is open. After close, only Stop, and effects re-check run state | G3, G10 |
| A ticket closed while waiting can still be approved | LangGraph README | Gate superseded by reconciliation, and decision time re-check | G11 |
| A public issue could plant a marker that suppresses the real comment | `github.py` comment at the marker lookup | Effect markers are trusted only when authored by our own bot identity | G9 |
| "Written back" shown with nothing written | Brief | Effect states come only from a read-back receipt | G8 |
| Nothing may be written before approval | `test_interrupt_blocks_write_back_on_every_branch`, topology test | Spy writer tests plus a static workflow proof on every template | G1, G2 |
| No cancellation, or closing the browser leaves a run spending | CrewAI README ("most important gap"), Strands README notes a dropped connection can't resume | Explicit cancel with a stop SLO and tests | C1 to C4 |
| A cancelled agent keeps generating | Strands `AbortableBedrockModel` | Carry the wrapper forward with its test | C2 |
| Permanently failed tickets re-ran on restart | LangGraph README | Error classes, and permanent means BLOCKED until a human retries | R1 |
| Client and botocore retries multiply | LangGraph README | One retry layer per call, and inner clients get `total_max_attempts=1` | R2 |
| No tracing in LangGraph, and cost figures were estimates | LangGraph and Strands READMEs | OTel everywhere, with estimates labelled and reconciled against billing | O1 |
| CloudFront strips `Authorization` on GET | CrewAI commit and [S55] | Forwarding policy with a template test, no SSE dependency | H1 |
| AgentCore stream read in 1 KiB blocks held back progress | `backends.py` comment and commit | Agents write events to a log, so the UI never reads that stream | H2 |
| Lambda reserved concurrency counted every request | Strands README | Spend control uses a DynamoDB semaphore and budgets | H3 |
| OAC to a Lambda URL needs `x-amz-content-sha256`, and `crypto.subtle` needs HTTPS | `web/src/lib/api.ts`, commit #4, [S56] | Use API Gateway, not a function URL. No browser hashing needed | H4 |
| Model IDs never verified, nothing deployed | All three READMEs | Model catalog, preflight, and D12 | D12 |
| Ticket text flows into prompts | All three READMEs | Layered controls: see threat model | T-series |
| Secrets in source can reach the model | LangGraph README: the denylist exempts source files | Scan tool output and patches, and the reviewer is not the only control | T4 |
| CrewAI substitution corrupted user text, and its stop sequence truncated drafts | `prompts.py`, commit log | One-pass rendering, no framework substitution, truncation detection | T2, A3 |
| Evaluator has no stall detection, and truncated output is not detected | CrewAI README | Loop caps, a no-progress rule, `max_tokens` is a failure | A3, A4 |
| A synthesis must not mark its own homework | Strands `report.py` | Code computes `degraded` from the run record | A5 |
| Reviewer-visible errors can leak URLs and paths | LangGraph README | Redact error text at the boundary | T5 |
| Identity was a shared token | All three READMEs | SSO, with no shared tokens | ADR-0008 |
| Target checkout was shallow, public and drifted | LangGraph README | GitHub App snapshots at a pinned SHA | ADR-0012 |
| Scale: list reads every checkpoint, polling reads all issues | LangGraph README | Indexed status, webhooks plus cursors | ADR-0017 |
| Node versions differed (20, 22, 24), port collisions, LAN access | READMEs, Strands PoC | `make doctor`, dedicated ports, no secure-context dependency | D0-02 |
| Stacked PRs conflict after squash merges, review loops need caps | Brief | Delivery rules in STAGES.md | Process |
| Reviewers found critical bugs CI missed | Commit logs, `test_review_regressions.py` | Independent review on every PR, and gate tests named per invariant | Process |

## 8. Facts not from vendor docs, and known unknowns

| Claim | Basis | Settled by |
|---|---|---|
| `git patch-id` ignores whitespace by default, and `--verbatim` does not | **Tested locally on 2026-10-31,** with the same diff indented two ways | D2-08 keeps a test |
| `Agent.as_tool`, `ConcurrentToolExecutor` | `poc-strands-orchestrator` code, against `strands-agents~=1.63` | D5-02 pins with tests |
| Text between tool calls can be hidden on Opus | `poc-strands-orchestrator/README.md`, never run live | D12-05 |
| Runtime VPC mode can support default-deny egress | Release notes record VPC egress support [S8]. Details not read | D12-08 |
| Browser host allowlisting, including redirects | Managed Chromium policies exist, and are fixed at `CreateBrowser` [S70]. Whether `URLAllowlist` needs `URLBlocklist: ["*"]`, and stops every redirect and fetch, is our knowledge, **unverified** | D8-03, D12-09 |
| A reused Cognito session cookie gives new tokens with no federated sign-in, and what `auth_time` holds then | **Unverified** | D12-10 |
| A blank attribute from the Inbound federation trigger clears the stored value | The mapping page says a blank source value does [S66], **not tested** | D12-10 |
| `POST /merges` on a fork reaching upstream commits, and promoting a fork SHA upstream | **Unverified** | D4-23 |
| Enqueueing a merge queue entry through the API | **Unverified** | D4-12 |
| App permission set beyond checks | Our knowledge of GitHub Apps, not checked on docs | D4-02, D4-15 |
| Reviews on draft PRs | **Unverified** | D4-10, D4-15 |
| Whether the personal account's plan allows draft PRs and branch protection on private repos | **Unverified** | D4-02 |
| A Cognito token refresh does not re-query the IdP | Our knowledge, **unverified** | D12-10 |
| Gateway accepts a platform-minted per-step JWT, and which claims Cedar sees | **Unverified** | D12-18 |
| AgentCore Identity can hold a Slack bot token and serve control-plane Lambdas | **Unverified** | D12-18 |
| Bedrock keeps billing after a disconnect or session stop | **Unverified** | D12-13 |
| Async merge details: permissions, error codes, what a moved head does | Changelog and REST summary only | D4-23 |
| Bot-owned forks with first-time-contributor settings and required checks | Docs suggest friction, **unverified** live | D4-17 |
| Code Interpreter Sandbox mode allows DNS | Secondary press report, AWS says "limited external network access" [S71] | D12-09 |
| New account Bedrock quotas | **Unverified** | D12-02 |
| WAF cannot attach to an HTTP API | Our knowledge | D11-13 |
| `workflow_dispatch` runs on a ref, with inputs | Our knowledge, not checked on docs | D8-11 |
| DynamoDB `TransactionConflict` is not modelled by fast stores | Our knowledge, not checked | D3-09 |

## Sources

- [S1] [strands-agents on PyPI](https://pypi.org/project/strands-agents/)
- [S2] [Strands: coordinate multiple agents](https://strandsagents.com/docs/user-guide/sdk/multi-agent/multi-agent-patterns/)
- [S3] [Strands: Swarm](https://strandsagents.com/docs/user-guide/sdk/multi-agent/swarm/), [strands.multiagent.graph](https://strandsagents.com/docs/api/python/strands.multiagent.graph/)
- [S4] [Strands: interrupts](https://strandsagents.com/latest/documentation/docs/user-guide/concepts/interrupts/)
- [S5] [Strands interrupts source (harness-sdk)](https://github.com/strands-agents/harness-sdk/blob/main/site/src/content/docs/user-guide/sdk/interrupts.mdx)
- [S6] [Strands: persist state across sessions](https://strandsagents.com/docs/user-guide/sdk/agents/session-management/), [concepts page](https://strandsagents.com/docs/user-guide/concepts/agents/session-management/)
- [S7] [AWS: Strands deep dive on architectures and observability](https://aws.amazon.com/blogs/machine-learning/strands-agents-sdk-a-technical-deep-dive-into-agent-architectures-and-observability/)
- [S8] [AgentCore release notes](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/release-notes.html)
- [S9] [AgentCore FAQs](https://aws.amazon.com/bedrock/agentcore/faqs/)
- [S10] [AgentCore harness GA announcement](https://aws.amazon.com/about-aws/whats-new/2026/06/amazon-bedrock-agentcore-harness-generally-available/)
- [S11] [Session storage preview announcement](https://aws.amazon.com/about-aws/whats-new/2026/03/bedrock-agentcore-runtime-session-storage/)
- [S12] [Runtime file system configurations](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html)
- [S13] [AWS::BedrockAgentCore::Runtime LifecycleConfiguration](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-bedrockagentcore-runtime-lifecycleconfiguration.html)
- [S14] [AgentCore quotas](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html)
- [S15] [Runtime sessions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-sessions.html)
- [S16] [Long-running agents on Runtime](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-long-run.html)
- [S17] [Code Interpreter](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-tool.html)
- [S18] [Browser](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-tool.html), [Memory](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/memory.html)
- [S19] [Harness observability and cost controls](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-operations.html)
- [S20] [Identity provider setup](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idps.html)
- [S21] [Identity: GitHub provider](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-idp-github.html)
- [S22] [AgentCore Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html)
- [S23] [AgentCore Policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html)
- [S24] [Step Functions: AgentCore harness integration](https://docs.aws.amazon.com/step-functions/latest/dg/connect-bedrockagentcore.html)
- [S25] [AWS: hosting coding agents on AgentCore](https://aws.amazon.com/blogs/machine-learning/its-safe-to-close-your-laptop-now-hosting-coding-agents-on-amazon-bedrock-agentcore/)
- [S26] [Claude Opus 5.5 model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-opus-5-5.html)
- [S27] [Claude Sonnet 5.5 model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-sonnet-5-5.html)
- [S28] [Claude Haiku 5.5 model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-haiku-5-5.html)
- [S29] [Claude Fable 5.1 model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-fable-5-1.html)
- [S30] [Inference profiles with limited model selection](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles-limited-model-selection.html)
- [S31] [Create an application inference profile](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles-create.html)
- [S32] [Step Functions integration patterns](https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html)
- [S33] [Step Functions quotas](https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html)
- [S34] [SendTaskSuccess](https://docs.aws.amazon.com/step-functions/latest/apireference/API_SendTaskSuccess.html)
- [S35] [Step Functions best practices](https://docs.aws.amazon.com/step-functions/latest/dg/sfn-best-practices.html)
- [S36] [GitHub: check runs](https://docs.github.com/en/rest/checks/runs?apiVersion=2022-11-28)
- [S37] [GitHub: create an installation access token](https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app)
- [S38] [GitHub: download a repository archive](https://docs.github.com/en/rest/repos/contents?apiVersion=2022-11-28#download-a-repository-archive-tar)
- [S39] [GitHub: validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [S40] [GitHub: webhook best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)
- [S41] [GitHub: protected branches REST](https://docs.github.com/en/rest/branches/branch-protection)
- [S42] [GitHub: available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets), [managing a branch protection rule](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule)
- [S43] [GitHub: managing a merge queue](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)
- [S44] [GitHub: merge a pull request](https://docs.github.com/en/rest/pulls/pulls?apiVersion=2022-11-28#merge-a-pull-request)
- [S45] [Jira Cloud: webhooks](https://developer.atlassian.com/cloud/jira/platform/webhooks/)
- [S46] [Jira: OAuth 2.0 3LO apps](https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/), [Jira Cloud REST v3: issues](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/), [developer community: transitions](https://community.developer.atlassian.com/t/how-should-i-get-the-correct-jira-transitions/67082)
- [S47] [Slack: verifying requests](https://docs.slack.dev/authentication/verifying-requests-from-slack/)
- [S48] [Slack: handling user interaction](https://docs.slack.dev/interactivity/handling-user-interaction/)
- [S49] [Linear: webhooks](https://linear.app/developers/webhooks)
- [S50] [Azure DevOps: webhooks](https://learn.microsoft.com/en-us/azure/devops/service-hooks/services/webhooks?view=azure-devops)
- [S51] [Cognito: third-party sign-in](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-identity-federation.html)
- [S52] [Cognito: OIDC IdPs](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-oidc-idp.html)
- [S53] [Cognito: SAML IdP notes](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-saml-idp-things-to-know.html)
- [S54] [Cognito: pre token generation trigger](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html)
- [S55] [CloudFront: custom origin request behaviour](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html)
- [S56] [CloudFront: restrict access to a Lambda function URL](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-lambda.html)
- [S57] [EventBridge Scheduler: schedule types](https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html)
- [S58] [AppSync Events](https://docs.aws.amazon.com/appsync/latest/eventapi/event-api-welcome.html)
- [S60] [GitHub: async merge API GA, 2026-10-01](https://github.blog/changelog/2026-10-01-github-async-merge-api-generally-available), [REST: pull requests](https://docs.github.com/en/rest/pulls/pulls?apiVersion=2026-03-10)
- [S61] [AgentCore: execute shell commands in Runtime sessions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-execute-command.html)
- [S62] [GitHub: REST branches, merge a branch](https://docs.github.com/en/rest/branches/branches?apiVersion=2022-11-28)
- [S63] [GitHub: workflow dispatch returns run IDs, 2026-02-19](https://github.blog/changelog/2026-02-19-workflow-dispatch-api-now-returns-run-ids)
- [S64] [AgentCore Policy: core concepts](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html)
- [S65] [VPC: security groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html)
- [S66] [Cognito: attribute mapping](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html)
- [S67] [Cognito: Lambda triggers, including federated users and inbound federation](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html)
- [S68] [Cognito: authorization endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html)
- [S69] [GitHub: Actions settings for a repository, fork workflows](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository), [approving runs from forks](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks), [secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [S70] [AgentCore Browser: enterprise policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-enterprise-policies.html)
- [S71] [AgentCore Code Interpreter: network modes](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-resource-management.html)
- [S72] [GitHub Actions: limits](https://docs.github.com/en/actions/reference/limits)
- [S73] [GitHub: webhook payloads](https://docs.github.com/en/webhooks/webhook-events-and-payloads), [API Gateway: HTTP API quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html)
- [S74] [Cognito: Inbound federation trigger](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-inbound-federation.html)
- [S75] [GitHub: events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [triggering a workflow](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)
- [S76] [GitHub: REST Actions permissions](https://docs.github.com/en/rest/actions/permissions?apiVersion=2022-11-28)
- [S59] [GitHub: troubleshooting required status checks](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
