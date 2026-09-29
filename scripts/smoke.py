#!/usr/bin/env python3
"""Exercise the public API; keep owner keys in memory and delete the test agent.

--execute makes a small, billable Bedrock request. --mcp additionally exercises
the public read-only DeepWiki MCP server (no personal account or OAuth needed).
"""
import argparse
import json
import time
import urllib.error
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--mcp", action="store_true")
    parser.add_argument("--verify-signatures", action="store_true")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    key = None
    verifier = None
    if args.verify_signatures:
        import importlib.util
        from pathlib import Path
        spec = importlib.util.spec_from_file_location("verify_card", Path(__file__).with_name("verify-card.py"))
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)

    def call(method, path, body=None, auth=True, expected=200, extra=None):
        headers = {"Content-Type": "application/json"}
        if auth and key:
            headers["Authorization"] = "Bearer " + key
        headers.update(extra or {})
        request = urllib.request.Request(
            base + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=headers,
            method=method,
        )
        try:
            response = urllib.request.urlopen(request, timeout=65)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.status != expected:
                # Never echo request headers, credentials, OAuth URLs or bodies.
                raise RuntimeError(f"{method} {path}: HTTP {response.status}, expected {expected}")
            data = response.read()
            return json.loads(data) if data else None

    assert call("GET", "/health", auth=False)["status"] == "ok"
    created = call("POST", "/v1/agents", {"name": "Disposable smoke test"}, auth=False, expected=201)
    agent = created["id"]
    key = created["owner_key"]
    path = "/v1/agents/" + agent
    try:
        card_path = "/agents/" + agent + "/agent-card.json"
        jwks = call("GET", "/.well-known/jwks.json", auth=False) if verifier else None
        if verifier:
            verifier.verify(call("GET", card_path, auth=False), jwks, base)
            print("PASS: card signed automatically at creation", flush=True)
        connectors = []
        instructions = "Answer concisely in French. Follow the user's request."
        request = "Réponds exactement : Le test fonctionne."
        if args.mcp:
            connector = call("POST", path + "/connectors", {
                "name": "DeepWiki public read-only documentation",
                "url": "https://mcp.deepwiki.com/mcp",
                "auth_type": "none",
                "allowed_tools": ["read_wiki_structure"],
            }, expected=201)
            connectors = [connector["id"]]
            tools = call("GET", path + "/connectors/" + connector["id"] + "/tools")
            assert any(t["name"] == "read_wiki_structure" for t in tools["tools"])
            instructions = (
                "Use read_wiki_structure once on repoName modelcontextprotocol/rust-sdk. "
                "Use the actual returned documentation structure to name three topics. "
                "Answer in three short bullet points in French."
            )
            request = "Consulte la structure de la documentation de modelcontextprotocol/rust-sdk et donne trois sujets."
            print("PASS: live MCP discovery and tool allowlist", flush=True)
        call("PUT", path + "/skills/assist", {
            "name": "Documentation assistant", "description": "Read public documentation",
            "instructions": instructions, "connector_ids": connectors,
        })
        card = call("GET", "/agents/" + agent + "/agent-card.json", auth=False)
        if verifier:
            verifier.verify(card, jwks, base)
            altered = dict(card, name="Tampered")
            try:
                verifier.verify(altered, jwks, base)
            except Exception:
                pass
            else:
                raise RuntimeError("Tampered card signature was accepted")
        assert card["skills"][0]["id"] == "assist"
        assert "instructions" not in card["skills"][0]
        call("GET", path, auth=False, expected=401)
        print("PASS: creation, owner authentication, skills and public card", flush=True)
        if args.execute:
            body = {"request": request, "skill_ids": ["assist"]}
            extra = {"Idempotency-Key": str(uuid.uuid4())}
            task = call("POST", path + "/tasks", body, expected=202, extra=extra)
            duplicate = call("POST", path + "/tasks", body, expected=202, extra=extra)
            assert duplicate["id"] == task["id"]
            deadline = time.monotonic() + 300
            while task["status"] in ("queued", "running") and time.monotonic() < deadline:
                time.sleep(2)
                task = call("GET", path + "/tasks/" + task["id"])
            assert task["status"] == "completed", f"Task ended as {task['status']}: {task.get('error')}"
            result = task["result"]
            assert result["model_calls"] >= 1
            if args.mcp:
                assert result["tool_calls"] >= 1
            print("PASS: task execution and idempotency", json.dumps({
                "model_calls": result["model_calls"], "tool_calls": result["tool_calls"],
                "cost_microusd": result["cost_microusd"], "text": result["text"],
            }, ensure_ascii=False), flush=True)
        old_key = key
        key = call("POST", path + "/key")["owner_key"]
        call("GET", path, expected=401, extra={"Authorization": "Bearer " + old_key})
        call("GET", path)
        print("PASS: owner key rotation", flush=True)
        if verifier:
            call("PATCH", path, {"name":"Updated signing test", "description":""})
            changed = call("GET", card_path, auth=False)
            assert changed["name"] == "Updated signing test"
            verifier.verify(changed, jwks, base)
            call("DELETE", path + "/skills/assist", expected=204)
            changed = call("GET", card_path, auth=False)
            assert changed["skills"] == []
            verifier.verify(changed, jwks, base)
            print("PASS: signature verification, tamper rejection, metadata and skill republication", flush=True)
    finally:
        call("DELETE", path, expected=204)
        call("GET", "/agents/" + agent + "/agent-card.json", auth=False, expected=404)
        print("PASS: cleanup", flush=True)


if __name__ == "__main__":
    main()
