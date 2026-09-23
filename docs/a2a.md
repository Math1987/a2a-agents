# A2A server

The service exposes A2A 1.0 JSON-RPC using the official `a2aproject/a2a-rs`
SDK (`a2a-lf` 0.3.1, `a2a-server-lf` 0.4.4). The protocol release reference is
v1.0.1; its wire version is `1.0`. Owner REST configuration remains available.

## Discover and invoke

Each agent has a public card at both:

- `/agents/{agent_id}/agent-card.json`
- `/agents/{agent_id}/.well-known/agent-card.json`

Read the card's `supportedInterfaces` to obtain its JSON-RPC URL:
`https://agents.aithos.app/agents/{agent_id}/a2a`.
There is no domain-wide default agent or agent directory.

This first deployment supports **asynchronous SendMessage only**. Set
`configuration.returnImmediately: true`, then poll `GetTask`. Omitted or false
values are rejected before a task is created: the default blocking behavior of
A2A 1.0 does not fit this deployment's 30-second HTTP gateway. This is a documented
interoperability limitation, not a claim of full A2A conformance. Streaming,
push notifications, files and extended cards are not enabled.

Example (use your own agent ID and keep the key in a local variable):

```sh
curl --fail-with-body -sS "https://agents.aithos.app/agents/$AGENT_ID/a2a" \
  -H "Authorization: Bearer $OWNER_KEY" \
  -H 'Content-Type: application/json' \
  -H 'A2A-Version: 1.0' \
  -d '{
    "jsonrpc": "2.0",
    "id": "request-1",
    "method": "SendMessage",
    "params": {
      "message": {
        "messageId": "unique-message-1",
        "role": "ROLE_USER",
        "parts": [{"text": "Présente les compétences que tu peux utiliser."}]
      },
      "configuration": {"returnImmediately": true}
    }
  }'
```

The response contains `result.task.id` and `result.task.contextId`. Submit a
`GetTask` request with `params: {"id": "TASK_ID"}` to retrieve state, public
conversation history and the final text artifact. Use a fresh `messageId` for
each new message; retain it for retries of the same message. JSON-RPC `id`
only correlates the request and response and does not deduplicate execution.

## Conversations, task states and retries

When information is missing, the worker can request clarification through its
internal `runtime_request_input` tool. The task becomes
`TASK_STATE_INPUT_REQUIRED` and its model checkpoint is persisted. Continue
with `SendMessage`, a **new** `messageId`, the existing `taskId`, and the user's
answer. The server infers `contextId` from the task when it is omitted. A supplied
context must match the task. The previous tool calls become conversation history;
the runtime does not execute them again when restoring that history.

Completed, failed, canceled and interrupted tasks cannot be restarted. For a new
task in the same logical conversation, omit `taskId` and supply its `contextId`.
Contexts group tasks and enforce ownership; automatic model-memory transfer
between separate completed tasks is not implemented. Continuations of an
input-required task do retain model context.

Message receipts and task transitions are atomic. A retry by the same caller
returns the existing task; reusing a message ID with altered contents fails.
Costs and token usage on the owner REST task record are cumulative across turns.
Private model checkpoints, MCP outputs, connector credentials and skill
instructions are not serialized in A2A history or artifacts.

An uncertain external write becomes a failed A2A task with an explicit uncertainty
message. It is never automatically replayed. A final model answer does not by
itself certify that a provider-side action succeeded; verify the provider result.

`CancelTask` cancels a queued task atomically, or returns the already canceled
task. Once processing has started it returns the standard non-cancelable error.
Canceling a task is not the same as deleting a calendar event.

`ListTasks` supports caller isolation, filters and pagination. Page sizes are
bounded to 100; the official SDK normalizes omitted/nonpositive sizes to 50.
Exact totals are computed over at most 1,000 task records, 8 MiB and 8 seconds
of queries for an agent. Responses are bounded to 512 KiB and may contain fewer
records than requested, with a continuation token. Above a query bound the operation
fails explicitly; `GetTask` remains available. Public conversations and model
checkpoints also have size/turn bounds to fit DynamoDB and Lambda limits.

By default the server offers the caller's permitted skills to the engine. The
optional application metadata `params.metadata.skill_ids` can narrow that set;
it never grants access. It is an Aithos convenience, not an A2A standard field.
For example, select `["reservation"]` to test a specific calendar skill. Skill
instructions describe behavior; connector `allowed_tools` enforces tool access.

## Owner and Aithos authentication

The existing owner key works on REST and A2A. Use it only in clients controlled by
the owner; it grants administration as well as invocation.

The server also implements optional **A2A-only JWT authentication**, using
`jsonwebtoken` and operator-configured JWKS. It is disabled until a trusted issuer
is configured. The future Aithos identity/token service is not implemented by
this repository, and the server does not mint invocation tokens.

Configure these non-secret settings together (Terraform `extra_environment`):

```text
A2A_ISSUER=https://YOUR_TRUSTED_ISSUER
A2A_JWKS_URL=https://YOUR_TRUSTED_ISSUER/keys
A2A_AUDIENCE=aithos-agents
```

Required token contract:

| Field | Meaning |
| --- | --- |
| `alg`, `kid` (header) | RS256 and the identifier of a trusted public JWKS key |
| `iss`, `aud` | Exact configured issuer and expected audience |
| `sub` | Stable caller identity, used to isolate tasks and contexts |
| `exp` | Expiration; optional `nbf` is also validated |
| `agent_id` | Exact target agent ID |
| `scope` | Must include `a2a:invoke` |
| `skill_ids` | Nonempty explicit list of permitted skill IDs; no wildcard |

The issuer must authorize these grants before signing them. Merely logging in
must not give access to every agent. JWTs cannot read or modify owner REST
resources. Callers can access only their own A2A tasks and contexts; the owner
can inspect and cancel the agent's A2A tasks. The model never receives the JWT.

JWKS are fetched from the configured HTTPS URL through the existing guarded
outbound client. The bounded cache refreshes on a request after its five-minute
TTL expires, or on a throttled unknown-key lookup. Tokens cannot select a discovery URL. Credentials for Google,
Notion or other connectors remain separate, encrypted and managed by the owner.

## Verification

The Python interoperability check requires Python 3.10 or newer.

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
python3 -m venv .build/interop
.build/interop/bin/python -m pip install -r scripts/interop-requirements.txt
cargo build --locked --bin a2a-agents
.build/interop/bin/python scripts/a2a-interop.py --start-server
# Live deployment; small billable model calls, disposable agent, no calendar:
cargo run --locked --example a2a_smoke -- https://agents.aithos.app
```

The live example uses the official Rust A2A client to discover the card, submit
and deduplicate a request, receive a clarification question, continue the same
task and verify its final artifact and cumulative accounting. It deletes its
temporary agent even when the exercise fails. OAuth consent and real calendar
writes are tested separately with the account owner.
