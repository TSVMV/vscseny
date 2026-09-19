#!/usr/bin/env bash
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/dist"
mkdir -p "$OUT"

export CGO_ENABLED=0

echo "building linux amd64..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$OUT/vscseny" "$ROOT"
chmod +x "$OUT/vscseny"

echo "building windows amd64..."
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$OUT/vscseny.exe" "$ROOT"

echo
echo "done:"
ls -l "$OUT/vscseny" "$OUT/vscseny.exe"
