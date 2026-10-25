#!/bin/sh
# Two processes in this netns. JSONL must name the one that connected.
# Localhost is hidden by Rustnet's default, so the connector dials a public address.
# The argv matches the supervisor, except the refresh is the minimum it allows.
set -eu

command -v rustnet >/dev/null
out=/tmp/rustnet.jsonl
err=/tmp/rustnet.err
rm -f "$out" "$err"
rustnet --headless --output jsonl --interface any \
  --no-resolve-dns --no-geoip --refresh-interval 1000 \
  >"$out" 2>"$err" &
pid=$!
cleanup() {
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT

sleep 30 &
sleep 2
if grep -q EPERM "$err" 2>/dev/null; then
  echo "BPF_EPERM"
  cat "$err"
  exit 2
fi

wget -q -T 8 -O /dev/null http://1.1.1.1/ >/tmp/wget.out 2>/tmp/wget.err &
sleep 4

if ! grep -q schema_version "$out"; then
  echo "NO_JSONL"
  cat "$err" || true
  exit 1
fi
if ! grep -q wget "$out"; then
  echo "CONNECTOR_NOT_NAMED"
  tail -c 4000 "$out" || true
  echo
  cat "$err" || true
  exit 1
fi
echo "rustnet names wget"
