#!/usr/bin/env python3
"""Operator-only backfill/rotation using the deployed API's non-secret config.

Run through scripts/with-env.py. Uses AWS credentials from the normal chain.
Scans agent META keys and updates only META revision + public CARD snapshots.
No owner key, connector secret, model or calendar is accessed.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--function-name', default='a2a-agents-poc-api')
parser.add_argument('--region', default='eu-west-3')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
binary = root / 'target/debug/a2a-agents'
if not binary.is_file():
    parser.error('Run cargo build --locked --bin a2a-agents first')
config = json.loads(subprocess.check_output([
    'aws', 'lambda', 'get-function-configuration', '--function-name', args.function_name,
    '--region', args.region, '--query', 'Environment.Variables', '--output', 'json',
]))
# Read only deployment settings; never inherit stale app overrides from the shell.
env = {k:v for k,v in os.environ.items() if not k.startswith(('APP_', 'A2A_'))}
env.update(config)
env.update(APP_MODE='publish-cards', AWS_DEFAULT_REGION=args.region, AWS_REGION=args.region)
if not config.get('APP_CARD_SIGNING_KEY_ID'):
    parser.error('Deploy the card-signing infrastructure/configuration first')
subprocess.run([str(binary)], cwd=root, env=env, check=True)
