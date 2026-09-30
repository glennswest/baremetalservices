#!/bin/bash
# Build both goldens and boot each the way it is used (#2):
#   sc-build test/run.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export TMPDIR="${TMPDIR:-$ROOT/tmp}"; mkdir -p "$TMPDIR"
go vet ./... && go test ./...
OUT="$(mktemp -d "$TMPDIR/bms-out.XXXXXX")"
bash deploy/build-golden.sh baremetalservices-maint "$OUT/maint"
bash test/boot-ovmf.sh disk "$OUT/maint/boot/baremetalservices-maint.iso"
bash deploy/build-golden.sh baremetalservices "$OUT/iso"
bash test/boot-ovmf.sh iso "$OUT/iso/boot/baremetalservices.iso"
bash test/boot-ovmf.sh bios "$OUT/iso/boot/baremetalservices.iso"
echo "test/run.sh: all PASS"
