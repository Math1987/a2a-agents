#!/usr/bin/env python3
"""Read-only verification of a deployed Aithos Agents stack after its smoke test.

Uses the standard AWS CLI credential chain. Run through scripts/with-env.py when
using this checkout's environment. Only the BUDGET ledger is read by default;
agent records, OAuth states and CREDENTIALS rows are never queried or scanned.
AWS stderr, Lambda's complete environment and raw DynamoDB payloads are never
printed. Optional bearer inspection reads only the explicitly named CONN row.

Examples:
  python3 scripts/with-env.py python3 scripts/check-deployment.py
  python3 scripts/with-env.py python3 scripts/check-deployment.py \
      --app-name a2a-agents-poc --base-url https://agents.aithos.app
  python3 scripts/with-env.py python3 scripts/check-deployment.py \
      --terraform-outputs /private/tmp/a2a-outputs.json --require-headroom

Exit 0 means all required checks passed. Exit 1 means a failed check; exit 2 means
invalid invocation or missing dependencies. SQS approximate counts may lag; a
delayed maintenance continuation is normal and does not fail the default check.
"""
import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request


class CheckError(Exception):
    """Safe public message: never include AWS stderr or a source payload."""


class Aws:
    def __init__(self, region=None):
        self.region = region

    def call(self, service, operation, *args, query=None):
        command = ["aws", service, operation, *args, "--output", "json", "--no-cli-pager"]
        if self.region:
            command += ["--region", self.region]
        if query:
            command += ["--query", query]
        env = os.environ.copy()
        env.update(AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off")
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)
        except (OSError, subprocess.TimeoutExpired):
            raise CheckError(f"AWS {service}/{operation} unavailable or timed out") from None
        if result.returncode:
            raise CheckError(f"AWS {service}/{operation} failed (exit {result.returncode}); check access and resource names")
        try:
            return json.loads(result.stdout)
        except (ValueError, TypeError):
            raise CheckError(f"AWS {service}/{operation} returned unreadable JSON") from None


def require(condition, message):
    if not condition:
        raise CheckError(message)


def integer(value, label):
    require(isinstance(value, (str, int)) and not isinstance(value, bool), f"{label} is not an integer")
    try:
        number = int(value)
    except (ValueError, TypeError):
        raise CheckError(f"{label} is not an integer") from None
    require(number >= 0, f"{label} is negative")
    return number


def configuration(args):
    outputs = {}
    if args.terraform_outputs:
        try:
            raw = json.loads(Path(args.terraform_outputs).read_text())
            require(isinstance(raw, dict) and "table_name" in raw and "resources" not in raw,
                    "Provide terraform output -json containing table_name, never Terraform state")
            outputs = {key: value.get("value") if isinstance(value, dict) and "value" in value else value
                       for key, value in raw.items()}
        except (OSError, ValueError, AttributeError):
            raise CheckError("Cannot read Terraform output JSON (do not provide a tfstate file)") from None
    published_functions = outputs.get("lambda_functions") or {}
    inferred_name = published_functions.get("api", "") if isinstance(published_functions, dict) else ""
    name = args.app_name or (inferred_name[:-4] if inferred_name.endswith("-api") else "a2a-agents-poc")
    functions = outputs.get("lambda_functions") or {mode: f"{name}-{mode}" for mode in ("api", "worker")}
    table = args.table or outputs.get("table_name") or name
    base = (args.base_url or outputs.get("public_url") or outputs.get("api_url") or "https://agents.aithos.app").rstrip("/")
    require(re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name), "Invalid application name")
    require(isinstance(table, str) and re.fullmatch(r"[a-zA-Z0-9_.-]{3,255}", table), "Invalid table name")
    parsed = urllib.parse.urlsplit(base)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment, "Base URL must be a public HTTPS URL without credentials")
    require(isinstance(functions, dict) and all(isinstance(functions.get(mode), str) for mode in ("api", "worker")),
            "Terraform lambda_functions must contain api and worker names")
    return name, table, base, functions, outputs


def check_budget(aws, table, month, limit, allow_zero, require_headroom):
    key = json.dumps({"pk": {"S": "BUDGET"}, "sk": {"S": month}})
    row = aws.call("dynamodb", "get-item", "--table-name", table, "--key", key, "--consistent-read",
                   query="Item.{Payload:payload.S,ExpiresAt:expires_at.N,Version:version.N}")
    if not row or row.get("Payload") is None:
        require(allow_zero, "Durable monthly budget ledger is absent; run the deployed paid smoke first")
        return "no ledger yet (allowed before paid smoke)"
    try:
        payload = json.loads(row["Payload"])
        used = integer(payload["used"], "Budget used")
        actual_limit = integer(payload["limit"], "Budget limit")
    except (ValueError, TypeError, KeyError):
        raise CheckError("Durable monthly budget has an invalid structure") from None
    require(actual_limit == limit, "Durable monthly budget limit differs from the expected cap")
    require(row.get("ExpiresAt") is None, "Durable monthly budget must not have an OAuth-state TTL")
    require(allow_zero or used > 0, "Durable model spending is zero; paid smoke has not been recorded")
    require(used < limit if require_headroom else used <= limit, "Durable spending exceeds the cap or required headroom is exhausted")
    return f"{month}: used={used} micro-USD, cap={actual_limit} micro-USD, durable/no TTL"


def check_envelope(aws, table, agent, connector):
    for value in (agent, connector):
        require(re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", value), "Invalid disposable agent or connector ID")
    key = json.dumps({"pk": {"S": "AGENT#" + agent}, "sk": {"S": "CONN#" + connector}})
    value = aws.call("dynamodb", "get-item", "--table-name", table, "--key", key, "--consistent-read",
                     query="Item.payload.S")
    try:
        record = json.loads(value)
        require(record.get("auth_type") == "bearer", "Selected connection is not a bearer test connector")
        envelope = json.loads(record["secret"])
        wrapped = base64.b64decode(envelope["key"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        require(len(wrapped) >= 32 and len(nonce) == 12 and len(ciphertext) >= 16,
                "Stored bearer secret does not have a valid KMS envelope shape")
    except (ValueError, TypeError, KeyError):
        raise CheckError("Selected connection does not contain a valid encrypted envelope") from None
    # Never print the record, encoded/decoded key, ciphertext or supplied token.
    return "bearer envelope present; wrapped data key, nonce and ciphertext checked without decryption"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app-name", help="Default: infer from Terraform Lambda names, otherwise a2a-agents-poc")
    parser.add_argument("--table", help="Default: Terraform table_name, otherwise app name (no -data suffix)")
    parser.add_argument("--base-url")
    parser.add_argument("--region", help="Otherwise use standard AWS CLI environment/configuration")
    parser.add_argument("--terraform-outputs", help="JSON produced by terraform output -json, never a tfstate")
    parser.add_argument("--budget-micro-usd", type=int, default=25_000_000)
    parser.add_argument("--month", default=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m"))
    parser.add_argument("--allow-zero-spend", action="store_true", help="Permit an absent/zero ledger before the paid smoke")
    parser.add_argument("--require-headroom", action="store_true", help="Require spending strictly below the configured cap")
    parser.add_argument("--require-drained", action="store_true", help="Also fail if tasks are visible, in flight or delayed")
    parser.add_argument("--check-bearer-envelope", nargs=2, metavar=("AGENT_ID", "CONNECTOR_ID"),
                        help="Inspect only this disposable bearer CONN row; never decrypt or read CREDENTIALS")
    args = parser.parse_args()
    if not shutil.which("aws"):
        parser.error("AWS CLI must be installed")
    require(args.budget_micro_usd >= 0, "Expected budget must be non-negative")
    require(re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", args.month), "Month must be YYYY-MM in UTC")
    name, table, base, functions, outputs = configuration(args)
    aws = Aws(args.region)
    failures = []

    def check(label, operation):
        try:
            detail = operation()
            print(f"PASS: {label}" + (f" — {detail}" if detail else ""), flush=True)
            return True
        except CheckError as error:
            failures.append(label)
            print(f"FAIL: {label} — {error}", flush=True)
            return False
        except (KeyError, TypeError, AttributeError, ValueError):
            failures.append(label)
            print(f"FAIL: {label} — unexpected response structure; source values omitted", flush=True)
            return False

    def health():
        try:
            with urllib.request.urlopen(base + "/health", timeout=20) as reply:
                body = reply.read(64 * 1024)
                require(reply.status == 200 and json.loads(body).get("status") == "ok", "Health response was not successful")
        except (urllib.error.URLError, ValueError, TimeoutError, OSError):
            raise CheckError("HTTPS health request failed") from None
        return "HTTPS endpoint responds"
    check("API health", health)

    def storage():
        description = aws.call("dynamodb", "describe-table", "--table-name", table,
            query="Table.{Status:TableStatus,BillingMode:BillingModeSummary.BillingMode,Indexes:GlobalSecondaryIndexes[].{Name:IndexName,Status:IndexStatus}}")
        require(description["Status"] == "ACTIVE", "DynamoDB table is not ACTIVE")
        require(description["BillingMode"] == "PAY_PER_REQUEST", "DynamoDB is not using on-demand billing")
        require(any(index["Name"] == "maintenance-index" and index["Status"] == "ACTIVE" for index in description["Indexes"]),
                "Maintenance index is absent or not ACTIVE")
        ttl = aws.call("dynamodb", "describe-time-to-live", "--table-name", table, query="TimeToLiveDescription")
        require(ttl["TimeToLiveStatus"] == "ENABLED" and ttl["AttributeName"] == "expires_at", "OAuth-state TTL is not enabled")
        return f"{table}: on demand, maintenance index and TTL enabled"
    check("DynamoDB configuration", storage)
    check("Durable global budget", lambda: check_budget(aws, table, args.month, args.budget_micro_usd,
                                                       args.allow_zero_spend, args.require_headroom))

    configs = {}
    for mode in ("api", "worker"):
        def check_lambda(mode=mode):
            config = aws.call("lambda", "get-function-configuration", "--function-name", functions[mode],
                query="{State:State,Update:LastUpdateStatus,Runtime:Runtime,Timeout:Timeout,Mode:Environment.Variables.APP_MODE,Table:Environment.Variables.APP_TABLE,Base:Environment.Variables.APP_PUBLIC_URL,Budget:Environment.Variables.APP_MONTHLY_BUDGET_MICRO_USD,Queue:Environment.Variables.APP_QUEUE_URL,Kms:Environment.Variables.APP_KMS_KEY_ID}")
            require(config["State"] == "Active" and config["Update"] == "Successful", "Lambda is not active with a successful update")
            require(config["Runtime"] == "provided.al2023" and config["Mode"] == mode, "Lambda runtime or application mode differs")
            require(config["Table"] == table and config["Base"].rstrip("/") == base, "Lambda table or public URL differs from deployment configuration")
            require(integer(config["Budget"], "Lambda budget") == args.budget_micro_usd, "Lambda global budget differs from expected cap")
            configs[mode] = config
            return f"active, expected public URL, cap={args.budget_micro_usd} micro-USD"
        check(f"Lambda {mode}", check_lambda)

    def kms():
        require(len(configs) == 2 and configs["api"]["Kms"] == configs["worker"]["Kms"], "Lambdas do not share the expected KMS key")
        key = configs["api"]["Kms"]
        description = aws.call("kms", "describe-key", "--key-id", key, query="KeyMetadata.{State:KeyState,Usage:KeyUsage}")
        require(description["State"] == "Enabled" and description["Usage"] == "ENCRYPT_DECRYPT", "KMS key is not enabled for encryption")
        rotation = aws.call("kms", "get-key-rotation-status", "--key-id", key, query="KeyRotationEnabled")
        require(rotation is True, "KMS automatic key rotation is disabled")
        return "shared encryption key enabled, automatic rotation enabled; no decryption performed"
    check("KMS", kms)

    for kind, expected_expression in (("oauth_maintenance", "cron(17 3 * * ? *)"), ("dispatch_pending", "rate(5 minutes)")):
        def schedule(kind=kind, expected_expression=expected_expression):
            config = aws.call("scheduler", "get-schedule", "--group-name", name,
                "--name", f"{name}-{kind.replace('_', '-')}",
                query="{State:State,Expression:ScheduleExpression,Timezone:ScheduleExpressionTimezone,Window:FlexibleTimeWindow.Mode,Target:Target.Arn,Input:Target.Input}")
            require(config["State"] == "ENABLED" and config["Window"] == "OFF", "Scheduler is disabled or has a flexible window")
            require(config["Expression"] == expected_expression and config["Timezone"] == "UTC", "Scheduler frequency or timezone differs from the expected configuration")
            require(config["Target"].endswith(":" + functions["worker"]), "Scheduler does not target the worker")
            try:
                require(json.loads(config["Input"]) == {"kind": kind}, "Scheduler event does not match the worker contract")
            except (TypeError, ValueError):
                raise CheckError("Scheduler event is not valid JSON") from None
            return f"enabled, {expected_expression}, UTC"
        check(f"Schedule {kind}", schedule)

    queues = {}
    for role, suffix, output_key in (("tasks", "tasks", "queue_url"), ("dead-letter", "dead-letter", "dead_letter_queue_url")):
        def queue(role=role, suffix=suffix, output_key=output_key):
            queue_url = outputs.get(output_key) or aws.call("sqs", "get-queue-url", "--queue-name", f"{name}-{suffix}", query="QueueUrl")
            attributes = aws.call("sqs", "get-queue-attributes", "--queue-url", queue_url,
                "--attribute-names", "QueueArn", "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible",
                "ApproximateNumberOfMessagesDelayed", "VisibilityTimeout", "SqsManagedSseEnabled", query="Attributes")
            visible = integer(attributes.get("ApproximateNumberOfMessages", "0"), "Visible messages")
            inflight = integer(attributes.get("ApproximateNumberOfMessagesNotVisible", "0"), "In-flight messages")
            delayed = integer(attributes.get("ApproximateNumberOfMessagesDelayed", "0"), "Delayed messages")
            require(attributes.get("SqsManagedSseEnabled") == "true", "SQS encryption is disabled")
            if role == "dead-letter":
                require(visible + inflight + delayed == 0, "Dead-letter queue is not empty; investigate failed jobs")
            else:
                require(len(configs) == 2 and all(config["Queue"] == queue_url for config in configs.values()), "Lambda queue URLs differ from the deployed task queue")
                require(integer(attributes["VisibilityTimeout"], "Visibility timeout") >= 6 * integer(configs["worker"]["Timeout"], "Worker timeout"), "SQS visibility is shorter than six worker timeouts")
                require(not args.require_drained or visible + inflight + delayed == 0, "Task queue is not yet fully drained")
            queues[role] = attributes
            return f"approximate visible={visible}, in-flight={inflight}, delayed={delayed} (delayed continuations may be normal)"
        check(f"SQS {role}", queue)

    def mapping():
        require("tasks" in queues, "Task queue attributes are unavailable")
        mappings = aws.call("lambda", "list-event-source-mappings", "--function-name", functions["worker"],
            query="EventSourceMappings[].{State:State,Source:EventSourceArn,Batch:BatchSize,Responses:FunctionResponseTypes}")
        require(any(row["State"] == "Enabled" and row["Source"] == queues["tasks"]["QueueArn"] and row["Batch"] == 1
                    and "ReportBatchItemFailures" in (row.get("Responses") or []) for row in mappings), "Worker SQS mapping is not enabled with batch size 1 and partial-failure reporting")
        return "enabled, one message per invocation, partial failures enabled"
    check("Worker queue mapping", mapping)
    if args.check_bearer_envelope:
        check("Disposable bearer storage", lambda: check_envelope(aws, table, *args.check_bearer_envelope))
    print(f"Deployment checks: {'FAILED (' + str(len(failures)) + ')' if failures else 'PASSED'}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CheckError as error:
        print(f"Check configuration failed: {error}", file=sys.stderr)
        sys.exit(2)
    except (KeyError, TypeError, AttributeError, ValueError):
        # Malformed provider/configuration values must not produce a traceback
        # containing full records or environment values.
        sys.exit("Deployment check received an unexpected response structure; no source data was printed.")
