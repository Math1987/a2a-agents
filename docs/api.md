# API guide

The examples use placeholders. `BASE` is your deployed API origin; `AGENT_ID`, `OWNER_KEY` and `CONNECTOR_ID` come from earlier responses. Use local mode for metadata tests, and the deployed HTTPS API for OAuth and durable execution.

```sh
BASE='https://agents.aithos.app'
AGENT_ID='AGENT_ID'
OWNER_KEY='OWNER_KEY'
CONNECTOR_ID='CONNECTOR_ID'
```

The JSON request limit is 64 KiB. Dates in API records are Unix timestamps in seconds. The [OpenAPI document](openapi.json) describes request and response shapes. Application errors use `{"error":"code"}`; malformed JSON or other Axum extraction failures can return plain text.

## 1. Create an agent

```sh
curl -sS "$BASE/v1/agents" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Project assistant","description":"Works with the project workspace"}'
```

Returns `201` with `id`, `name`, `description`, `created_at`, `card_url`, and the **one-time** `owner_key`. Creation is public and makes no model call. All `/v1/agents/{agent}/...` operations require that agent's owner key:

```sh
curl -sS "$BASE/v1/agents/$AGENT_ID" -H "Authorization: Bearer $OWNER_KEY"
```

There is no user account or lost-key recovery in this version. `POST /v1/agents/{agent}/key` returns a replacement key and immediately invalidates the previous one. `PATCH /v1/agents/{agent}` requires `name`; omitted `description` becomes an empty string.

## 2. Add an OAuth connector

```sh
curl -sS "$BASE/v1/agents/$AGENT_ID/connectors" \
  -H "Authorization: Bearer $OWNER_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Project Notion","url":"https://mcp.notion.com/mcp","auth_type":"oauth"}'
```

Returns `201` with the connection ID and `authorization_required`. This example uses Notion's documented remote MCP endpoint; it does not claim that this deployment has already completed a real Notion consent flow. Adding a connector stores its configuration; it does not establish or verify access yet.

Start the consent flow:

```sh
curl -sS "$BASE/v1/agents/$AGENT_ID/connectors/$CONNECTOR_ID/authorize" \
  -H "Authorization: Bearer $OWNER_KEY" \
  -H 'Content-Type: application/json' \
  -d '{}'
```

The service discovers OAuth metadata and attempts dynamic client registration when no client ID is supplied. Open the returned `authorization_url` in your browser and approve access. For a provider requiring prior registration, pass `{"client_id":"CLIENT_ID","client_secret":"CLIENT_SECRET","scopes":["PROVIDER_SCOPE"]}` instead. `client_secret` and `scopes` are optional. Register this exact callback when required:

```text
https://agents.aithos.app/oauth/callback/AGENT_ID/CONNECTOR_ID
```

The provider redirects the browser there with `code` and `state`, and optionally `iss`. The callback validates the pending state and PKCE flow, exchanges the code and stores tokens. You do not manually submit the owner key to this callback. A successful response reports `status: connected`.

`expires_in: 600` applies only to the initial browser authorization attempt. **Connected credentials have no 10-minute expiry or database TTL.** The runtime renews access tokens as needed. A daily maintenance schedule also refreshes idle connections when their seven-day maintenance date arrives. Rotated tokens and OAuth client credentials persist encrypted across Lambda restarts.

Provider rules still control grant lifetime. Notion currently documents refresh-token expiry after 30 days without a successful refresh or an absolute 180 days after initial consent, whichever comes first. Reconnect after revocation or absolute expiry. See [Notion's token lifecycle](https://developers.notion.com/guides/mcp/build-mcp-client#token-lifecycle); other providers differ. No several-month duration is guaranteed for every connector.

Inspect connection state and available tools:

```sh
curl -sS "$BASE/v1/agents/$AGENT_ID/connectors" -H "Authorization: Bearer $OWNER_KEY"
curl -sS "$BASE/v1/agents/$AGENT_ID/connectors/$CONNECTOR_ID/tools" -H "Authorization: Bearer $OWNER_KEY"
```

The tools request connects to the remote server and returns its MCP tool definitions. Connection states are `authorization_required`, `authorization_pending`, `connected`, and `reauthorization_required`; disconnected entries disappear from listings. Repeat `/authorize` to reconnect using the durable registration parameters.

Tool definitions can change during a task. The worker refreshes discovery on the existing MCP session after each completed tool call, so configuration and execution tools exposed in successive steps can be used by the same task. This API discovery request uses its own session and does not expose another task's temporary configuration state. Exact `allowed_tools` names apply to dynamically exposed tools too; permission for a configuration tool does not automatically permit an execution tool with another name.

## Alternative: a connector accepting a bearer token

```sh
curl -sS "$BASE/v1/agents/$AGENT_ID/connectors" \
  -H "Authorization: Bearer $OWNER_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Calendar tools","url":"https://MCP_HOST/mcp","auth_type":"bearer","token":"PROVIDER_TOKEN","allowed_tools":["PROVIDER_TOOL_NAME"]}'
```

Use this only if the MCP server supports bearer credentials. `auth_type: none` is also supported for public MCP servers. Tokens must not be embedded in URLs or skills. Secret fields never appear in connector responses. When omitted, `allowed_tools` is `["*"]`; pass exact tool names to restrict access, or `[]` to expose none. These settings are chosen when creating the connection; this release has no connector PATCH route.

## 3. Add a skill

Skills are arbitrary Markdown instructions associated with connector IDs belonging to the same agent. The URL supplies the skill ID; a body `id` is optional and is overwritten by the path.

```sh
curl -sS -X PUT "$BASE/v1/agents/$AGENT_ID/skills/project-summary" \
  -H "Authorization: Bearer $OWNER_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Project summary","description":"Read the current project status","instructions":"Find the requested project using the available workspace tools. Read relevant pages and summarize progress and blockers. Ask for clarification if several projects match. This skill only reads information.","connector_ids":["CONNECTOR_ID"]}'
```

A skill may have no connectors for a text-only task. It needs `name`, `description` and nonempty `instructions`. Instructions are visible to the owner and the model, not on the public card. Tool permissions are enforced by the backend; writing “read only” in Markdown alone does not remove write tools. Restrict `allowed_tools` accordingly when read-only access is required.

```sh
curl -sS "$BASE/agents/$AGENT_ID/agent-card.json"
```

The public card exposes descriptions, skill names and access requirements. It advertises the A2A 1.0 `JSONRPC` interface at `/agents/{agent}/a2a`. See the [A2A guide](a2a.md) for asynchronous invocation, durable conversations, SDK clients and optional invocation-only JWT authentication. The REST routes below remain owner-only.

## 4. Submit and poll a task

```sh
curl -sS "$BASE/v1/agents/$AGENT_ID/tasks" \
  -H "Authorization: Bearer $OWNER_KEY" \
  -H 'Idempotency-Key: project-review-001' \
  -H 'Content-Type: application/json' \
  -d '{"request":"Summarize the current project and its blockers.","skill_ids":["project-summary"]}'
```

Returns `202` and a task record. For a new task, omitted or empty `skill_ids` selects all currently configured skills; at least one valid skill is required. Reusing the same idempotency key with the same request text and submitted `skill_ids` returns the original task, even after the configured skills change or are deleted. Omitted `skill_ids` and `[]` are equivalent. A changed request or explicit skill selection returns `409 idempotency_key_reused`. Omitting the header creates a new task every time.

```sh
TASK_ID='TASK_ID'
curl -sS "$BASE/v1/agents/$AGENT_ID/tasks/$TASK_ID" -H "Authorization: Bearer $OWNER_KEY"
```

| Status | Meaning |
| --- | --- |
| `queued` | Persisted and awaiting dispatch |
| `running` | Claimed by a worker |
| `completed` | Structured output is in `result`, including `text`, `usage`, `cost_microusd`, `model_calls` and `tool_calls` |
| `failed` | Read the sanitized `error`, e.g. `global_monthly_budget_exhausted` |
| `interrupted` | Timeout, worker interruption or uncertain tool outcome; an external action may already have happened |

Queued delivery can be retried; an already running task is never blindly executed again. Before resubmitting an interrupted task under a new idempotency key, check the external system. Neither task idempotency nor SQS deduplication can guarantee exactly-once writes to arbitrary MCP tools.

For completed tasks, `result.usage` contains aggregate `input_tokens` and `output_tokens`. Costs are integer micro-USD: `1_000_000` means 1 USD. `result` is `null` until completion.

`completed` confirms that the agent returned a final response, not that every requested external action succeeded. Read `result.text` and verify any created object with its provider. A failure to refresh MCP tools after an operation marks the task `interrupted`; check external state before submitting a new task because the preceding operation may already have succeeded.

## Cleanup and routes

`DELETE /v1/agents/{agent}/connectors/{connection}` removes local credentials and disables the connection. It does not call a provider token-revocation endpoint; revoke the grant at the provider too when needed. `DELETE /v1/agents/{agent}` disables the owner key and public card, and clears private records. Already-dispatched external actions cannot be undone by deletion.

| Route | Methods | Access |
| --- | --- | --- |
| `/`, `/health`, `/openapi.json` | GET | Public |
| `/v1/agents` | POST | Public |
| `/v1/agents/{agent}` | GET, PATCH, DELETE | Owner |
| `/v1/agents/{agent}/key` | POST | Owner |
| `/agents/{agent}/agent-card.json` | GET | Public |
| `/v1/agents/{agent}/skills` | GET | Owner |
| `/v1/agents/{agent}/skills/{skill}` | PUT, DELETE | Owner |
| `/v1/agents/{agent}/connectors` | GET, POST | Owner |
| `/v1/agents/{agent}/connectors/{connection}` | DELETE | Owner |
| `/v1/agents/{agent}/connectors/{connection}/authorize` | POST | Owner |
| `/v1/agents/{agent}/connectors/{connection}/tools` | GET | Owner |
| `/oauth/callback/{agent}/{connection}` | GET | Valid one-time OAuth state |
| `/v1/agents/{agent}/tasks` | GET, POST | Owner |
| `/v1/agents/{agent}/tasks/{task}` | GET | Owner |
