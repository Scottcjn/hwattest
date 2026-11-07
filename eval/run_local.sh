#!/bin/bash
# Collect the LOCAL evaluation dataset (this machine only; no other lab hosts).
# Bare metal idle + under CPU load, a Docker container (non-VM control), KVM
# guests (stock and VM-hiding) and TCG emulation (stock and hardened).
# Usage: eval/run_local.sh [OUTDIR]   (default eval/data/local)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
OUT="${1:-$HERE/data/local}"
mkdir -p "$OUT"
PY="${PYTHON:-python3}"
HOST="${HOST_ALIAS:-$(hostname -s)}"
NB="${N_BARE:-10}"; NL="${N_LOAD:-5}"; NV="${N_VM:-5}"; NE="${N_EMU:-3}"

$PY "$HERE/collect.py" --label bare_metal --sublabel idle --host-alias "$HOST" --runs "$NB" --out "$OUT/bare_idle.jsonl"
$PY "$HERE/collect.py" --label bare_metal --sublabel load8 --host-alias "$HOST" --runs "$NL" --load 8 --out "$OUT/bare_load8.jsonl"
$PY "$HERE/collect.py" --label bare_metal --sublabel load16 --host-alias "$HOST" --runs "$NL" --load 16 --out "$OUT/bare_load16.jsonl"

if command -v docker >/dev/null && docker image inspect python:3.12-slim >/dev/null 2>&1; then
  docker run --rm --network none --user "$(id -u):$(id -g)" \
    -v "$REPO/src:/w/src:ro" -v "$REPO/eval/collect.py:/w/eval/collect.py:ro" -v "$OUT:/out" \
    python:3.12-slim python3 /w/eval/collect.py --label container --sublabel docker \
    --host-alias "$HOST-docker" --runs "$NV" --out /out/container_docker.jsonl
fi

if [ -w /dev/kvm ]; then
  PORT=2251 "$HERE/vm/run_guest.sh" kvm "$NV" "$OUT/vm_kvm.jsonl"
  PORT=2252 "$HERE/vm/run_guest.sh" kvm_hidden "$NV" "$OUT/vm_kvm_hidden.jsonl"
fi
PORT=2253 "$HERE/vm/run_guest.sh" tcg "$NE" "$OUT/emu_tcg.jsonl"
PORT=2254 "$HERE/vm/run_guest.sh" tcg_hardened "$NE" "$OUT/emu_tcg_hardened.jsonl"
echo "done: $(cat "$OUT"/*.jsonl | wc -l) records in $OUT"
