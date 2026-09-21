#!/usr/bin/env python3
"""Execute with local credentials, without sourcing shell code or printing secrets."""
import json
import os
from pathlib import Path
import re
import shlex
import sys

def parse(text):
    values = {}
    allowed = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
               "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "GH_TOKEN"}
    while text.strip():
        text = text.lstrip()
        if text.startswith("{"):
            obj, end = json.JSONDecoder().raw_decode(text)
            mapping = {"AccessKeyId": "AWS_ACCESS_KEY_ID", "SecretAccessKey": "AWS_SECRET_ACCESS_KEY", "SessionToken": "AWS_SESSION_TOKEN"}
            if not all(isinstance(obj.get(k), str) for k in mapping):
                raise ValueError("Invalid credential-process JSON")
            values.update({v: obj[k] for k, v in mapping.items()})
            text = text[end:]
            continue
        line, _, text = text.partition("\n")
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(r"(?:github_pat_|ghp_)[A-Za-z0-9_]+", line):
            values["GH_TOKEN"] = line
            continue
        key, sep, value = line.partition("=")
        if not sep or key not in allowed:
            raise ValueError("Unsupported credential entry")
        parts = shlex.split(value, comments=True)
        if len(parts) != 1:
            raise ValueError("Invalid credential quoting")
        values[key] = parts[0]
    return values

if __name__ == "__main__":
    env = os.environ.copy()
    try:
        path = Path(__file__).resolve().parents[1] / ".env"
        if path.exists():
            env.update(parse(path.read_text()))
    except (ValueError, KeyError):
        sys.exit("Could not parse .env; expected credential JSON, dotenv entries, or a GitHub token.")
    if env.get("AWS_ACCESS_KEY_ID"):
        env.pop("AWS_PROFILE", None)
        env.pop("AWS_DEFAULT_PROFILE", None)
    env.setdefault("AWS_DEFAULT_REGION", "eu-west-3")
    env["AWS_PAGER"] = ""
    if len(sys.argv) < 2:
        sys.exit("Usage: scripts/with-env.py COMMAND [ARGS...]")
    os.execvpe(sys.argv[1], sys.argv[1:], env)
