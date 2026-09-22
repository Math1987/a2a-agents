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

## Provider authorization still required

A real authenticated connector needs its account owner's consent. For each chosen provider, verify authorization, tool discovery, an allowed read and refresh after the original access token expires. Multi-month grant validity remains subject to provider expiry, revocation and policy; it cannot be established by this short test run.
