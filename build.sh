#!/usr/bin/env bash
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/dist"
mkdir -p "$OUT"

export CGO_ENABLED=0

echo "building linux amd64..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$OUT/vscseny-linux-amd64" "$ROOT"
chmod +x "$OUT/vscseny-linux-amd64"

echo "building windows amd64..."
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$OUT/vscseny-windows-amd64.exe" "$ROOT"

if command -v zip >/dev/null 2>&1; then
  echo "packaging zip archives..."
  (cd "$OUT" && zip -9 -q vscseny-linux-amd64.zip vscseny-linux-amd64)
  (cd "$OUT" && zip -9 -q vscseny-windows-amd64.zip vscseny-windows-amd64.exe)
fi

echo
echo "done:"
ls -l "$OUT"
