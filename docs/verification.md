# Phase 1 verification — 2026-09-21

## Completed before deployment

- 54 Rust tests passed: 33 library tests, 15 HTTP API/contract tests and 6 DynamoDB SDK tests.
- `cargo clippy --locked --all-targets -- -D warnings` and `cargo fmt --all -- --check` passed.
- Terraform modules initialized and validated. Read-only plans show 7 bootstrap resources and 27 application resources to create; no existing resource would change or be destroyed.
- Source staging excludes `.env`, Terraform state, build outputs and credential-shaped strings.
- The first published revision passed GitHub Actions, including Linux Rust tests, Clippy and Terraform validation. Follow-up commits run the same checks; cloud deployment remains disabled until explicitly enabled after infrastructure approval.

Tests exercise the actual Axum router and official SDKs against controlled local HTTP endpoints. They cover OAuth PKCE, state consumption and expiry, reconstruction after a process change, token rotation and refresh leases, MCP calls, Bedrock request serialization and retry behavior, DynamoDB conditional writes and pagination, agent isolation, idempotency and the global budget under concurrent reservations. Fixtures do not replace live provider authorization.

## Real model and connector check

The local API was started with the provided AWS credentials in `eu-west-3`, using Bedrock's EU Claude Haiku 4.5 inference profile. The public DeepWiki MCP server was attached without authentication, limited to `read_wiki_structure`.

```sh
python3 scripts/smoke.py http://127.0.0.1:3188 --execute --mcp
```

The full flow passed: create an agent, save a skill, discover MCP tools, read the public card, reject unauthenticated management, submit/deduplicate a task, invoke the real MCP tool through the model, read the final response, rotate the key and remove the temporary agent.

The successful run used **2 model calls and 1 MCP tool call**, with a calculated model cost of **4,479 micro-USD (0.004479 USD)** at configured prices. Local records and the local budget were in memory; this does not yet verify AWS persistence.

## Deployment checks still required

Creating the isolated AWS stack awaits explicit deployment approval. After deployment, rerun the smoke script against the API Gateway URL to verify Lambda, SQS, KMS and DynamoDB together, and inspect the durable budget ledger.

A real authenticated connector needs its account owner's consent. For each chosen provider, verify authorization, tool discovery, an allowed read and refresh after the original access token expires. Multi-month grant validity remains subject to provider expiry, revocation and policy; it cannot be established by this short test run.
