# Phase 1 verification — 2026-09-22

## Completed before deployment

- 54 Rust tests passed: 33 library tests, 15 HTTP API/contract tests and 6 DynamoDB SDK tests.
- `cargo clippy --locked --all-targets -- -D warnings` and `cargo fmt --all -- --check` passed.
- Terraform modules initialized and validated. Read-only plans show 7 bootstrap resources and 27 application resources to create; no existing resource would change or be destroyed.
- Source staging excludes `.env`, Terraform state, build outputs and credential-shaped strings.
- Published revisions pass GitHub Actions, including Linux Rust tests, Clippy and Terraform validation. Code deployment is enabled only after infrastructure approval and live verification.

Tests exercise the actual Axum router and official SDKs against controlled local HTTP endpoints. They cover OAuth PKCE, state consumption and expiry, reconstruction after a process change, token rotation and refresh leases, MCP calls, Bedrock request serialization and retry behavior, DynamoDB conditional writes and pagination, agent isolation, idempotency and the global budget under concurrent reservations. Fixtures do not replace live provider authorization.

## Real model and connector check

The local API was started with the provided AWS credentials in `eu-west-3`, using Bedrock's EU Claude Haiku 4.5 inference profile. The public DeepWiki MCP server was attached without authentication, limited to `read_wiki_structure`.

```sh
python3 scripts/smoke.py http://127.0.0.1:3188 --execute --mcp
```

The full flow passed: create an agent, save a skill, discover MCP tools, read the public card, reject unauthenticated management, submit/deduplicate a task, invoke the real MCP tool through the model, read the final response, rotate the key and remove the temporary agent.

The successful run used **2 model calls and 1 MCP tool call**, with a calculated model cost of **4,479 micro-USD (0.004479 USD)** at configured prices. Local records and the local budget were in memory; this does not yet verify AWS persistence.

## AWS deployment

The stack was deployed on 2026-09-22 to **https://agents.aithos.app**, in AWS account `128066560720`, region `eu-west-3`. Public DNS delegation was verified before deployment. Route 53 routes the subdomain to API Gateway, with an ACM certificate validated through DNS. The canonical hostname is also used for Agent Cards and OAuth callbacks.

Terraform created 7 bootstrap resources and 33 application resources, including the custom domain. Existing resources were not modified. Both states are stored in the private, versioned, encrypted S3 backend; post-deployment plans report no changes.

The deployed smoke test passed with **2 Bedrock calls and 1 real MCP tool call**, costing **4,318 micro-USD (0.004318 USD)** at configured prices. It exercised API Gateway, Lambda, SQS and DynamoDB, then rotated the key and deleted its disposable agent.

A separate disposable bearer connector proved KMS data-key generation, encrypted storage in DynamoDB and decryption by Lambda during real MCP tool discovery. Only a generated dummy token was used, and the test agent was removed afterwards.

The read-only [deployment checker](../scripts/DEPLOYMENT-CHECKS.md) passed: the durable September ledger recorded 4,318 micro-USD against a 25,000,000 micro-USD cap; runtime configuration, KMS, schedules and task queues were correct. Both the task queue and dead-letter queue were empty.

## Owner-guided Google Calendar check

The account owner manually created an agent, authorized Pipedream MCP at `https://mcp.pipedream.net/v2` with `mcp` and `offline_access`, and confirmed its connected status. Tool discovery and model-driven calendar listing succeeded. A controlled availability check also matched an event entered by the owner: one half-hour interval was busy and the immediately following interval was free, with the correct UTC conversion.

Free-form slot suggestions initially contained incorrect weekdays and a timezone conversion. Refining the skill improved the response, but did not establish reliable date calculation: a later answer still omitted the requested raw time field and expanded the requested date range. These are remaining output-quality limitations, separate from connector access.

An event-creation attempt returned a final response reporting uncertainty. Pipedream's response referenced a dynamically exposed `run_…` tool, whereas the worker had only discovered tools at task startup. This is not a successful creation check, even though the task status was `completed`. The runtime now refreshes tool discovery within the existing session after each call. Regression tests cover the configuration-to-execution transition; a real provider creation still needs a new owner-guided test after checking that the first attempt did not create an event.

The dynamic-discovery correction passes **62 Rust tests**: 41 library tests, 15 API tests and 6 DynamoDB SDK tests. A local Streamable HTTP server exercises the actual MCP SDK's session preservation and changing tool schemas. Worker tests enforce exact allowlists and revocation; engine tests cover new execution tools, stale batch calls, invalid discovery, timeouts and removal of every tool. Bedrock SDK HTTP tests verify that token counting and inference receive the same history even after every tool is removed.

On 2026-09-23, after confirming the first event was absent, the owner submitted a new reservation on a future half-hour interval. The agent returned an event ID, exact timestamps and a provider link; the owner confirmed the event in Google Calendar. The task used 4 model calls and 3 MCP calls, costing 30,908 micro-USD. This validates owner-guided creation after the dynamic-tool correction, not autonomous negotiation between two calendar agents.

No personal calendar identifiers, owner keys or OAuth credentials are included in this report. The original task is not automatically replayed.

## A2A server verification — 2026-09-23

The official Rust SDK provides the A2A 1.0 JSON-RPC transport and protocol types.
The complete local suite passes **92 Rust tests**: 67 library tests, 2 actual
SDK/HTTP integration tests, 15 REST/contract tests and 8 storage/SDK tests.
Formatting and Clippy with warnings denied also pass.

The official Python SDK 1.1.5 independently parses the card with strict ProtoJSON
and passes discovery, asynchronous SendMessage, idempotent retries, GetTask,
ListTasks and cancellation against the local server. This check runs in CI,
uses no model and deletes its disposable agent.

Regression coverage includes JWT signature/issuer/audience/agent/skill checks,
caller isolation, bounded JWKS rotation, private checkpoint filtering, atomic
conversation receipts, input-required continuation, cumulative budget accounting,
old-worker fencing, bounded pagination and checkpoint limits. Restoring a
checkpoint does not replay earlier MCP calls. The SDK normalizes nonpositive
list page sizes; the documented endpoint otherwise limits pages to 100 records.

The deployed endpoint requires explicit asynchronous requests and polling.
Streaming, push notifications and the default blocking SendMessage mode are not
supported. Aithos JWT verification remains disabled until an issuer is configured.
See [the A2A guide](a2a.md) for these compatibility limits and the live smoke command.

## Remaining provider checks

A real authenticated connector needs its account owner's consent. For each chosen provider, verify authorization, tool discovery, an allowed read and refresh after the original access token expires. Multi-month grant validity remains subject to provider expiry, revocation and policy; it cannot be established by this short test run.
