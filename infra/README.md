# Deployment

The isolated `a2a-agents-poc` stack uses account `128066560720`, region `eu-west-3`. It does not manage any Calendar POC resources. The AWS provider refuses other accounts.

## Resources and cost

- Two Rust Lambda functions (`api`, `worker`), HTTP API Gateway, no VPC or NAT.
- One on-demand DynamoDB table, one task queue plus a dead-letter queue, managed encryption at rest.
- One customer-managed KMS key for connector credential encryption (a standing key charge, plus request charges).
- CloudWatch logs retained 14 days; access logs omit URLs, query strings, headers, and bodies.
- Daily OAuth maintenance and a five-minute task-dispatch recovery schedule; these invoke the same worker.
- One versioned, private, encrypted S3 state bucket and a GitHub OIDC code-deployment role.
- No provisioned concurrency, EC2, Fargate, load balancer, or permanent worker.

The application model budget defaults to **25 USD per UTC calendar month**, shared by all agents. API requests, DynamoDB, KMS, logs, schedules and other infrastructure costs are separate usage charges. The model budget is not an AWS account spending cap.

## First deployment

Authenticate locally with the intended AWS profile. Do not copy credentials into Terraform variables, GitHub, or state. Build the application from the repository root with `bash scripts/build-lambda.sh` (Cargo Lambda 1.9.2 and Zig 0.16.0). For a project-local installation, run `python3 -m venv .build/tools`, then `.build/tools/bin/python -m pip install -r scripts/build-requirements.txt`. The script automatically detects this ignored local environment. The Linux standard library must be installed with `rustup target add x86_64-unknown-linux-gnu`.

1. Run `terraform -chdir=infra/bootstrap init`.
2. Run `terraform -chdir=infra/bootstrap plan -out=bootstrap.tfplan`, inspect the plan, then `terraform -chdir=infra/bootstrap apply bootstrap.tfplan`. The GitHub provider already exists in this AWS account. The exact immutable subject configured for this repository is `repo:Math1987@55652304/a2a-agents@1379233470:ref:refs/heads/main`. Do not replace it with a wildcard.
3. The bootstrap starts with local state because its bucket does not exist yet. Immediately back up that state securely. Once the bucket exists, add an ignored `infra/bootstrap/backend.generated.tf` containing a `terraform { backend "s3" {} }` block and run `terraform -chdir=infra/bootstrap init -migrate-state -backend-config='bucket=aithos-a2a-agents-tfstate-128066560720-eu-west-3' -backend-config='key=bootstrap/terraform.tfstate' -backend-config='region=eu-west-3' -backend-config='encrypt=true' -backend-config='use_lockfile=true'` to persist it remotely.
4. Run `terraform -chdir=infra/app init -backend-config=backend.hcl.example`. Native S3 lockfiles prevent concurrent Terraform writes.
5. Run `terraform -chdir=infra/app plan -out=app.tfplan`, inspect the plan, then `terraform -chdir=infra/app apply app.tfplan`.
6. Read the URL with `terraform -chdir=infra/app output -raw api_url`; test its `/health` route and the complete API flow.

The API's execute-api endpoint is the stable `APP_PUBLIC_URL` and OAuth callback origin. Keep the API resource when making updates. For a custom domain later, update provider OAuth registrations and the application URL together.

Commit `.terraform.lock.hcl` for each module; never commit `.terraform/`, local/remote state files, plans, backend generated files, `.env`, or the built binary. Provider checksums can be expanded with `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64`.

## CI and updates

Pull requests run Rust tests, Clippy, formatting and Terraform validation without AWS credentials. Deployment is disabled unless the repository variable `DEPLOY_ENABLED` is exactly `true`, so the first push to `main` runs checks only. After the initial AWS deployment has been authorized, bootstrap and application infrastructure have been applied, and the live service has been validated, enable subsequent code deployments with `gh variable set DEPLOY_ENABLED --repo Math1987/a2a-agents --body true`. Successful `main` builds then assume the repository/branch-specific OIDC role and update only the two Lambda code packages, then check `/health`. To pause automatic deployments, set the same variable to `false`.

The role cannot change infrastructure, IAM policies, read the application table or decrypt tokens directly. Code deployed into a Lambda does inherit that function's runtime permissions, so main-branch and workflow review remain security boundaries. Infrastructure updates are applied separately with an operator identity using the instructions above. Build the same revision before Terraform apply, because the plan includes the package hash and can otherwise redeploy an older binary.

The workflow uses direct Lambda zip uploads; `build-lambda.sh` enforces the 50 MiB package limit. If the executable grows beyond that, add a dedicated artifact S3 bucket and scoped upload permissions.

## Persistence and scheduling contract

The table has string keys `pk` and `sk`, an integer optimistic-lock `version`, and a JSON string `payload`. Application records can include these optional top-level index/expiry attributes:

| Attribute | Type | Meaning |
| --- | --- | --- |
| `maintenance_pk` | String | `CONNECTION` for due OAuth connections, `TASK` for queued tasks needing dispatch |
| `maintenance_due` | Number | Next due Unix timestamp in seconds |
| `expires_at` | Number | DynamoDB TTL, only for genuinely temporary records |

Query `maintenance-index` by partition and `maintenance_due <= now`, paginating until completion. The index is eventually consistent, so the worker must atomically claim each item and recheck its current state; the schedule is a recovery mechanism, not the primary task dispatcher. Never attach a 10-minute TTL to a durable OAuth connection or refresh token. OAuth state expiration must also be checked in the application because DynamoDB TTL deletion is asynchronous.

The worker receives SQS messages with batch size 1 and supports `ReportBatchItemFailures`. Its timeout is 300 seconds and task queue visibility is 1,800 seconds. Scheduled payloads are `{"kind":"oauth_maintenance"}` and `{"kind":"dispatch_pending"}`. Schedule delivery and SQS are at least once: renewal, claims and side-effect recovery must be coordinated in DynamoDB.

Monitor Lambda errors, task failures, and the dead-letter queue. Inspect failed tasks before redriving them: a timeout does not prove that an external write did not happen. OAuth providers can still require reauthorization when consent is revoked or refresh-token lifetime ends.
