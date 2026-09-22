# Read-only checks after deployment

First run the disposable public API smoke against the deployed domain:

```sh
python3 scripts/smoke.py https://agents.aithos.app --execute --mcp
```

Then inspect the real AWS deployment and durable budget:

```sh
python3 scripts/with-env.py python3 scripts/check-deployment.py \
  --app-name a2a-agents-poc --base-url https://agents.aithos.app \
  --require-headroom
```

`infra/app/storage.tf` names the table with `var.name`: the default table is
`a2a-agents-poc`, **not** `a2a-agents-poc-data`. Override with `--table` when needed.
The CLI uses the normal AWS credential chain and accepts `--region`.

For an alternate deployment, use the non-secret Terraform outputs:

```sh
python3 scripts/with-env.py terraform -chdir=infra/app output -json > /private/tmp/a2a-outputs.json
python3 scripts/with-env.py python3 scripts/check-deployment.py \
  --terraform-outputs /private/tmp/a2a-outputs.json --base-url https://agents.aithos.app
```

The checker makes only `GET`/describe/list requests. It verifies the current UTC
month's `BUDGET` ledger (`used > 0`, cap `25,000,000` micro-USD), both Lambda
configurations, the maintenance index and state TTL, KMS configuration, scheduled
events, queue counts and Lambda's SQS mapping. It does not query OAuth state or
`CREDENTIALS` records, decrypt secrets, receive queue messages or invoke a worker.
`--allow-zero-spend` is useful before the first paid smoke. `--require-headroom`
requires spending strictly below the cap. The cap applies to model calls, not the
whole AWS bill.

Queue counts are approximate and can lag. Delayed maintenance continuations and
normal in-flight messages do not fail the default check; dead-letter messages do.
Use `--require-drained` only after all test work and continuations have settled.

## Optional disposable bearer envelope check

This is a separate, explicitly mutating test; the checker itself remains read-only.
Run it only after deployment. Do not use a real account token for this check.

1. Create a disposable agent through `POST /v1/agents`. Keep its returned owner
   key only in process memory; do not echo it, put it on a command line, or save it
   in the repository.
2. With the owner key in the HTTP authorization header, create a connector with
   `POST /v1/agents/{agent_id}/connectors` and this body:

   ```json
   {
     "name": "Disposable KMS storage check",
     "url": "https://mcp.deepwiki.com/mcp",
     "auth_type": "bearer",
     "token": "disposable-dummy-value-not-a-real-credential",
     "allowed_tools": ["read_wiki_structure"]
   }
   ```

   Creating the connector stores the dummy value with a KMS envelope and does
   not call an external tool. Do not run a task with this connector.
3. Record only the returned **agent and connector IDs**, then inspect that exact
   `CONN` record:

   ```sh
   python3 scripts/with-env.py python3 scripts/check-deployment.py \
     --base-url https://agents.aithos.app \
     --check-bearer-envelope AGENT_ID CONNECTOR_ID
   ```

   The checker validates the wrapped data key, nonce and ciphertext structure.
   It prints no record, token, encrypted key or ciphertext and performs no
   decryption. This verifies encrypted storage through the deployed API; it does
   not prove a provider's OAuth consent or refresh behavior.
4. In a `finally` block of the same API client, delete the disposable agent with
   `DELETE /v1/agents/{agent_id}` and its owner key. Do not leave test credentials
   or agents behind when an intermediate check fails.
