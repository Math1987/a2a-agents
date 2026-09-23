#!/usr/bin/env python3
"""Check A2A 1.0 with the official Python SDK against a local metadata-only API.

Setup (Python >=3.10):
  python3 -m venv .build/interop
  .build/interop/bin/python -m pip install -r scripts/interop-requirements.txt
  cargo build --locked --bin a2a-agents
  .build/interop/bin/python scripts/a2a-interop.py --start-server

Without --start-server, the optional URL targets an already running local API.
It must have no worker/Bedrock enabled: tasks remain queued and are cancelled.
The temporary agent is deleted in finally; owner credentials stay in memory.
"""

import argparse
import asyncio
import ipaddress
import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.types import a2a_pb2 as a2a
from google.protobuf.json_format import ParseDict


DEFAULT_URL = "http://127.0.0.1:3188"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def local_url(value):
    parsed = urlsplit(value)
    try:
        loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    require(
        parsed.scheme == "http"
        and loopback
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and parsed.path in ("", "/"),
        "This metadata-only test accepts only a loopback HTTP origin.",
    )
    return value.rstrip("/")


def start_server(base):
    # App::local currently advertises this exact origin in its Agent Card.
    require(base == DEFAULT_URL, "--start-server requires the default localhost URL.")
    try:
        with socket.create_connection(("127.0.0.1", 3188), timeout=0.2):
            raise RuntimeError("Port 3188 is occupied; refusing to reuse an unknown server.")
    except (ConnectionRefusedError, TimeoutError):
        pass
    root = Path(__file__).resolve().parents[1]
    binary = root / "target" / "debug" / "a2a-agents"
    require(binary.is_file(), "Run cargo build --locked --bin a2a-agents first.")
    env = {
        key: value
        for key, value in os.environ.items()
        if key != "APP_LOCAL_BEDROCK" and not key.startswith("A2A_")
    }
    env.update(APP_MODE="local", APP_LISTEN="127.0.0.1:3188")
    return subprocess.Popen(
        [str(binary)], cwd=root, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )


async def wait_for_server(http, base, server):
    deadline = asyncio.get_running_loop().time() + 15
    while asyncio.get_running_loop().time() < deadline:
        require(server.poll() is None, "The local API process exited during startup.")
        try:
            response = await http.get(base + "/health", timeout=0.5)
            if response.status_code == 200:
                return
        except httpx.TransportError:
            pass
        await asyncio.sleep(0.1)
    raise RuntimeError("The local API did not become healthy within 15 seconds.")


async def rest(http, method, url, *, expected=200, body=None):
    response = await http.request(method, url, json=body)
    require(response.status_code == expected,
            f"REST {method} returned HTTP {response.status_code}, expected {expected}.")
    return response.json() if response.content else None


async def exercise(base, public):
    created = await rest(public, "POST", base + "/v1/agents", expected=201,
                         body={"name": "Disposable Python SDK interoperability test"})
    path = base + "/v1/agents/" + created["id"]
    card_path = "/agents/" + created["id"] + "/.well-known/agent-card.json"
    private_instructions = "PRIVATE_INTEROP_INSTRUCTIONS: answer simple text requests."
    async with httpx.AsyncClient(
        headers={"Authorization": "Bearer " + created["owner_key"]},
        timeout=10, trust_env=False, follow_redirects=False,
    ) as owner:
        client = None
        try:
            await rest(owner, "PUT", path + "/skills/interop", body={
                "name": "Interop", "description": "Simple text assistance",
                "instructions": private_instructions, "connector_ids": [],
            })
            raw_card = await rest(public, "GET", base + card_path)
            # Resolver supports legacy compatibility and ignores unknown fields.
            # Also parse strictly to catch noncanonical ProtoJSON on the wire.
            strict_card = ParseDict(raw_card, a2a.AgentCard())
            card = await A2ACardResolver(public, base, card_path).get_agent_card()
            require(card == strict_card, "Agent Card needs legacy normalization.")
            require(private_instructions not in str(raw_card), "Card leaked private instructions.")
            require([skill.id for skill in card.skills] == ["interop"], "Skill discovery failed.")
            require(bool(card.security_requirements), "Missing security requirements.")
            require("owner" in card.security_requirements[0].schemes,
                    "Owner authentication was not parsed by the official SDK.")
            require(card.security_schemes["owner"].http_auth_security_scheme.scheme.lower() == "bearer",
                    "Owner bearer scheme was not parsed by the official SDK.")
            require(not card.capabilities.streaming and not card.capabilities.push_notifications,
                    "Unsupported transports were advertised.")
            require(bool(card.supported_interfaces), "No A2A interface advertised.")
            for interface in card.supported_interfaces:
                endpoint = urlsplit(interface.url)
                origin = urlsplit(base)
                require((endpoint.scheme, endpoint.netloc) == (origin.scheme, origin.netloc),
                        "The card advertised a different origin; refusing to send an owner key.")
                require(interface.protocol_binding == "JSONRPC" and interface.protocol_version == "1.0",
                        "Unexpected A2A binding or protocol version.")
            print("PASS: strict ProtoJSON card, skills and bearer requirements", flush=True)

            client = await create_client(card, ClientConfig(
                httpx_client=owner, streaming=False, polling=True,
                supported_protocol_bindings=["JSONRPC"],
            ))
            request = a2a.SendMessageRequest(
                message=a2a.Message(message_id=str(uuid4()), role=a2a.ROLE_USER,
                                    parts=[a2a.Part(text="Metadata interoperability test only.")]),
                configuration=a2a.SendMessageConfiguration(return_immediately=True),
                metadata={"skill_ids": ["interop"]},
            )
            chunks = [chunk async for chunk in client.send_message(request)]
            require(len(chunks) == 1 and chunks[0].HasField("task"), "SendMessage did not return a task.")
            task = chunks[0].task
            require(task.status.state == a2a.TASK_STATE_SUBMITTED,
                    "The server executed the task; use local metadata-only mode.")
            duplicate = [chunk async for chunk in client.send_message(request)]
            require(duplicate[0].task.id == task.id, "Message retry created a duplicate task.")
            fetched = await client.get_task(a2a.GetTaskRequest(id=task.id, history_length=1))
            require(fetched.id == task.id and len(fetched.history) == 1,
                    "GetTask/historyLength is incompatible with the official SDK.")
            require(fetched.history[0].message_id == request.message.message_id,
                    "Message history did not round-trip.")
            listed = await client.list_tasks(a2a.ListTasksRequest(
                context_id=task.context_id, page_size=1, history_length=0,
            ))
            require(len(listed.tasks) == 1 and listed.tasks[0].id == task.id,
                    "ListTasks did not find the task.")
            require(listed.page_size == 1 and listed.total_size == 1 and not listed.next_page_token,
                    "ListTasks pagination metadata is incompatible.")
            require(not listed.tasks[0].history, "historyLength=0 exposed messages.")
            canceled = await client.cancel_task(a2a.CancelTaskRequest(id=task.id))
            require(canceled.status.state == a2a.TASK_STATE_CANCELED,
                    "CancelTask did not cancel the queued task.")
            fetched = await client.get_task(a2a.GetTaskRequest(id=task.id))
            require(fetched.status.state == a2a.TASK_STATE_CANCELED, "Cancellation was not durable.")
            print("PASS: official SDK SendMessage, retry, GetTask, ListTasks and CancelTask", flush=True)
        finally:
            await rest(owner, "DELETE", path, expected=204)
            await rest(public, "GET", base + card_path, expected=404)
            if client is not None:
                await client.close()
            print("PASS: disposable agent removed; no Bedrock or MCP invocation", flush=True)


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", nargs="?", default=DEFAULT_URL)
    parser.add_argument("--start-server", action="store_true")
    args = parser.parse_args()
    base = local_url(args.base_url)
    server = None
    try:
        if args.start_server:
            server = start_server(base)
        async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as public:
            if server is not None:
                await wait_for_server(public, base, server)
            await exercise(base, public)
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(main())
    except Exception as error:
        # Do not dump HTTP payloads or credentials through SDK exception logs.
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print("FAIL: " + detail, file=sys.stderr)
        sys.exit(1)
