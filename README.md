# Aithos Agents

Configurable multi-tenant agents: create an agent publicly, retain its single owner key, attach Markdown skills and remote MCP connectors, then submit REST or A2A tasks to a Rust worker powered by Amazon Bedrock.

Public API: **https://agents.aithos.app**. See the [live OpenAPI contract](https://agents.aithos.app/openapi.json), [API guide](docs/api.md) and [verification report](docs/verification.md).

The owner key authorizes configuration and invocation. The public card advertises an **A2A 1.0 JSON-RPC endpoint** built with the official Rust SDK. This first A2A deployment uses explicit asynchronous requests and polling, and supports durable clarification/continuation. Optional invocation-only JWT verification is ready for a trusted Aithos issuer; issuing these tokens, the Aithos client, an agent directory and a web interface remain future work. See the [A2A guide and compatibility limits](docs/a2a.md).

## Start locally

Requires Rust 1.95 or later.

```sh
cargo run
```

The API listens on `http://127.0.0.1:3188`. This default mode uses an in-memory store and an ephemeral encryption key. It supports configuration and task submission; submitted tasks remain queued. Restarting discards all local data and credentials.

```sh
curl -sS http://127.0.0.1:3188/health
curl -sS http://127.0.0.1:3188/v1/agents \
  -H 'Content-Type: application/json' \
  -d '{"name":"Project assistant","description":"Helps with the current project"}'
```

Save the returned `owner_key` securely: it is only returned at creation and key rotation. It cannot be recovered from the database. See the [complete API flow](docs/api.md) and [OpenAPI contract](docs/openapi.json).

For an explicit local Bedrock smoke test with valid AWS credentials and model access:

```sh
AWS_PROFILE=aithos-prod AWS_REGION=eu-west-3 APP_LOCAL_BEDROCK=1 cargo run
```

This mode makes real, billable model calls. Its local budget and task history reset on restart; use the deployed DynamoDB stack for durable global spending control. OAuth redirects require a public HTTPS callback, so the default loopback server is not an OAuth deployment. The `.env` file is not loaded by `cargo run`; the optional `python3 scripts/with-env.py COMMAND ...` helper loads operator credentials without evaluating shell code.

## Deploy and verify

Follow [AWS deployment instructions](infra/README.md). Terraform creates two Lambda functions, API Gateway HTTP API, DynamoDB, SQS, KMS and EventBridge schedules. No EC2, Fargate or permanently running OAuth process is required.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Tests exercise the actual Axum routes, encryption, agent isolation, concurrent task deduplication, budget reservations, SDK OAuth/MCP exchanges and Bedrock HTTP serialization against controlled fixtures. A real provider consent flow still requires its account owner. External Notion/Calendly authorization is not implied by passing those tests.

Run a disposable-agent smoke test against a local or deployed API:

```sh
python3 scripts/smoke.py https://YOUR_API_ID.execute-api.eu-west-3.amazonaws.com
python3 scripts/smoke.py https://YOUR_API_ID.execute-api.eu-west-3.amazonaws.com --execute
python3 scripts/smoke.py https://YOUR_API_ID.execute-api.eu-west-3.amazonaws.com --execute --mcp
```

The first command tests metadata, authentication, skills, key rotation and cleanup without model inference. `--execute` makes billable model calls and checks task execution/idempotency. `--mcp` additionally uses DeepWiki's public read-only MCP tools; it does not authorize a personal calendar. The script keeps keys in memory and deletes its test agent in `finally`.

## Budget and scope

One shared model budget defaults to **25 USD per UTC calendar month**, across all agents. Before each paid inference, the worker counts input tokens and reserves the input cost plus the configured maximum output cost. Known actual usage settles the reservation; uncertain responses retain it. There are no per-agent usage quotas.

Infrastructure and third-party connector charges are outside this model budget. Execution, payload and tool-result bounds keep individual tasks within Lambda limits. They are technical bounds, not a guarantee that public API traffic has no infrastructure cost.

Supported connectors are remote MCP servers over public HTTPS using Streamable HTTP, with OAuth 2 + PKCE, bearer tokens, or no authentication. Hosted local/stdio MCP programs are outside this release. Provider compatibility depends on its metadata, registration requirements and available tools; arbitrary URLs do not guarantee interoperability.

See [architecture and failure handling](docs/architecture.md) for durable authorization, token refresh, isolation and interrupted-task behavior.
