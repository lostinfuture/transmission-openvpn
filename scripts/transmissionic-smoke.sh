#!/bin/sh
# Smoke Transmissionic against the Transmission in this image.
# A JSON error on the malformed torrent-add is a pass. A dead daemon or a blank UI is not.
set -eu

home=/opt/transmission-ui/transmissionic
test -f "$home/index.html"
test -f "$home/LICENSE"
test -f "$home/NOTICE"
grep -q "Copyright (c) 2021 Transmissionic" "$home/LICENSE"
grep -q "Copyright (c) 2026 lostinfuture" "$home/NOTICE"
grep -q "script-src 'self'" "$home/index.html"
base=/tmp/transmissionic-smoke
cfg=$base/config
dl=$base/downloads
mkdir -p "$cfg" "$dl"
cat > "$cfg/settings.json" <<'EOF'
{
  "download_dir": "/tmp/transmissionic-smoke/downloads",
  "rpc_authentication_required": false,
  "rpc_whitelist_enabled": false,
  "rpc_host_whitelist_enabled": false
}
EOF

export TRANSMISSION_WEB_HOME="$home"
transmission-daemon \
  --foreground \
  --config-dir "$cfg" \
  --rpc-bind-address 127.0.0.1 \
  --port 9091 \
  --no-portmap \
  --no-lpd \
  > "$base/daemon.log" 2>&1 &
pid=$!
cleanup() {
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT

web=http://127.0.0.1:9091/transmission/web/
ok=0
i=0
while [ "$i" -lt 30 ]; do
  if wget -q -O "$base/web.html" "$web"; then
    ok=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$ok" -ne 1 ]; then
  echo "web UI did not come up" >&2
  cat "$base/daemon.log" >&2 || true
  exit 1
fi
if ! grep -q "<title>Transmissionic</title>" "$base/web.html"; then
  echo "web UI is not Transmissionic" >&2
  exit 1
fi
if ! grep -q "script-src 'self'" "$base/web.html"; then
  echo "web UI lost its script policy" >&2
  exit 1
fi
if ! grep -q 'src="js/' "$base/web.html"; then
  echo "web UI script is not relative" >&2
  exit 1
fi
wget -q -O "$base/default.json" "${web}default.json"
if ! grep -q '^{}$' "$base/default.json" && ! grep -q '^{}[[:space:]]*$' "$base/default.json"; then
  echo "default.json is not empty" >&2
  cat "$base/default.json" >&2 || true
  exit 1
fi

rpc=http://127.0.0.1:9091/transmission/rpc
# BusyBox wget does not print response headers on a 409, so read them with nc.
hdr=$(printf 'GET /transmission/rpc HTTP/1.0\r\n\r\n' | nc -w 3 127.0.0.1 9091 || true)
sid=$(printf '%s\n' "$hdr" | sed -n 's/.*[Xx]-[Tt]ransmission-[Ss]ession-[Ii]d: *//p' | tr -d '\r' | head -n 1)
if [ -z "$sid" ]; then
  echo "no transmission session id" >&2
  printf '%s\n' "$hdr" >&2
  exit 1
fi

rpc_call() {
  wget -q -O "$2" --header="X-Transmission-Session-Id: $sid" --post-data="$1" "$rpc"
}

rpc_call '{"method":"session-get"}' "$base/session.json"
grep -q '"result"' "$base/session.json"
rpc_call '{"method":"torrent-get","arguments":{"fields":["id","name"]}}' "$base/tget.json"
grep -q '"result"' "$base/tget.json"

meta='ZDg6YW5ub3VuY2UyNzpodHRwOi8vMTI3LjAuMC4xOjkvYW5ub3VuY2U0OmluZm9kNjpsZW5ndGhpMWU0Om5hbWU1OmEudHh0MTI6cGllY2UgbGVuZ3RoaTE2Mzg0ZTY6cGllY2VzMjA6hvfkN/qlp/zhXR3cuerq6jd2Z7hlZQ=='
rpc_call "{\"method\":\"torrent-add\",\"arguments\":{\"metainfo\":\"$meta\",\"files-wanted\":\"nope\",\"priority-high\":[999999]}}" "$base/add.json" || true
if ! kill -0 "$pid" 2>/dev/null; then
  echo "transmission-daemon exited after malformed torrent-add" >&2
  cat "$base/daemon.log" >&2 || true
  exit 1
fi
rpc_call '{"method":"session-get"}' "$base/session2.json"
grep -q '"result"' "$base/session2.json"
echo "transmissionic smoke ok"
