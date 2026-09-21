#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Prefer project-local tooling so macOS developers do not need a global installation.
if [[ -x .build/tools/bin/cargo-lambda ]]; then
  export PATH="$PWD/.build/tools/bin:$PATH"
fi

if ! cargo lambda --version >/dev/null 2>&1; then
  echo 'Cargo Lambda is required. Create .build/tools with python3 -m venv, then install scripts/build-requirements.txt in it.' >&2
  exit 1
fi

cargo lambda build --release --x86-64 --bin a2a-agents --locked
mkdir -p .build
install -m 755 target/lambda/a2a-agents/bootstrap .build/bootstrap
python3 - <<'PY'
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

with ZipFile('.build/lambda.zip', 'w', ZIP_DEFLATED, compresslevel=9) as archive:
    archive.write('.build/bootstrap', 'bootstrap')
size = Path('.build/lambda.zip').stat().st_size
if size > 50 * 1024 * 1024:
    raise SystemExit('Lambda zip exceeds the 50 MiB direct-upload limit; use an S3 artifact before deploying.')
print(f'Lambda package ready: {size / 1024 / 1024:.1f} MiB')
PY
