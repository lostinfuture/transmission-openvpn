# transmission-openvpn

[![Build and Publish Docker Image](https://github.com/lostinfuture/transmission-openvpn/actions/workflows/build-docker.yml/badge.svg)](https://github.com/lostinfuture/transmission-openvpn/actions/workflows/build-docker.yml)
[![Test](https://github.com/lostinfuture/transmission-openvpn/actions/workflows/test.yml/badge.svg)](https://github.com/lostinfuture/transmission-openvpn/actions/workflows/test.yml)
[![Docker Image Version](https://img.shields.io/docker/v/lostinfuture/transmission-openvpn?label=lostinfuture%2Ftransmission-openvpn&style=flat-square)](https://hub.docker.com/r/lostinfuture/transmission-openvpn/tags)
[![Docker Image Size](https://img.shields.io/docker/image-size/lostinfuture/transmission-openvpn/latest?style=flat-square)](https://hub.docker.com/r/lostinfuture/transmission-openvpn/tags)
[![Docker Pulls](https://img.shields.io/docker/pulls/lostinfuture/transmission-openvpn?style=flat-square)](https://hub.docker.com/r/lostinfuture/transmission-openvpn)

Transmission and OpenVPN in one container. The torrent client starts after the tunnel is up. A kill switch drops traffic that would leave any other way.

The image is Alpine, with Transmission 4.1.4, OpenVPN 2.7.8, and a static Go supervisor. Baked provider configs come from [haugene/vpn-configs-contrib](https://github.com/haugene/vpn-configs-contrib) at commit `ff3753aadd96cca4b056f60930fa577e6e2986a3`. Your own `.ovpn` is a bind mount. It runs on `linux/amd64`, `linux/arm64`, and `linux/arm/v7`.

The environment variables, volume paths (`/data`, `/config`, `/etc/openvpn/custom`, `/scripts`), and port `9091` follow [haugene/docker-transmission-openvpn](https://github.com/haugene/docker-transmission-openvpn).

## What it does

OpenVPN comes up first. Transmission starts when the tunnel is up. On stop, Transmission exits first, then OpenVPN. Remotes are resolved once, when OpenVPN starts, and rewritten to IP addresses, so a reconnect does not need DNS inside the tunnel.

`LOCAL_NETWORK` keeps a route to your LAN on the original gateway. The kill switch is on unless `ENABLE_KILLSWITCH=false`.

## Advantages

- **Tunnel before torrents.** Transmission stays down until hook-up.
- **Kill switch on by default.** `ENABLE_UFW=false` does not turn it off. UFW is not installed.
- **Your config, or a baked provider.** `list-providers` prints every baked file. NordVPN and PIA are fetched by the supervisor. IPVanish is not installed.
- **Port forwarding for PIA and Proton.** NAT-PMP is built in. The `natpmpc` package is not installed.
- **Stock web UI, plus two optional ones.** Flood and Transmissionic are in the image. The stock UI is the default.
- **Pinned components.** Transmission, OpenVPN, the contrib commit, the web UI archives, and Rustnet stay on the versions in the Dockerfile. The Monday rebuild refreshes Alpine packages and does not float those pins.
- **Three architectures.** amd64, arm64, and armv7. Rustnet is included on amd64 and arm64.

## Before you start

- Docker, with `NET_ADMIN` and `/dev/net/tun` available to the container.
- OpenVPN credentials, or a provider that takes a token.
- A download directory and a Transmission config directory.
- For a custom provider: a file named `vpn.ovpn` in the directory you mount at `/etc/openvpn/custom`.
- `stop_grace_period: 45s`. Teardown can take about 33 seconds. Docker's default 10 seconds sends `SIGKILL` before that finishes.

Port `9091` is the web UI. With no RPC username or password, anyone who can reach that port can add and remove torrents. Keep it off your router's port-forwarding list. Set a password below if the LAN is shared.

Do not commit `.ovpn` files, credential files, or `.env`. `.gitignore` ignores them. The fixture under `internal/openvpn/testdata/` stays in git.

## Start

`docker-compose.yml` is the custom-provider file. Edit the three paths, export `OPENVPN_USERNAME` and `OPENVPN_PASSWORD`, then:

```bash
docker compose up -d
```

`OPENVPN_CONFIG=vpn` reads `/etc/openvpn/custom/vpn.ovpn`. An empty `OPENVPN_CONFIG` reads `default.ovpn`. Copying the file without the ovpn mount exits before OpenVPN, because that config is not in the image.

`restart: unless-stopped` brings the container back when Docker starts. That is Docker's restart policy. `SELFHEAL` is a different switch and stays off in this file. `examples/custom.yml` is the same provider setup with no restart policy, so the two stay easy to tell apart.

### Docker CLI

```bash
docker run -d \
  --name transmission-openvpn \
  --restart unless-stopped \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --security-opt no-new-privileges:true \
  --stop-timeout 45 \
  -p 9091:9091 \
  --tmpfs /run \
  -v /path/to/downloads:/data \
  -v /path/to/transmission/config:/config \
  -v /path/to/ovpn:/etc/openvpn/custom:ro \
  -e OPENVPN_PROVIDER=custom \
  -e OPENVPN_CONFIG=vpn \
  -e OPENVPN_USERNAME \
  -e OPENVPN_PASSWORD \
  -e LOCAL_NETWORK=192.168.1.0/24 \
  -e PUID=1000 -e PGID=1000 \
  ghcr.io/lostinfuture/transmission-openvpn:edge
```

`PUID` and `PGID` default to 1000. Explicit `0` runs Transmission as root and logs a warning.

### Check it from a laptop

Open `http://<server-ip>:9091/`. Find the address with `hostname -I` or in your router's device list.

```bash
docker logs -f transmission-openvpn
```

### Other providers

| File | Provider |
| :--- | :--- |
| `examples/airvpn.yml` | Baked AirVPN `default.ovpn` |
| `examples/nordvpn.yml` | One NordVPN server, chosen at start |
| `examples/pia.yml` | PIA from the public server list |
| `examples/protonvpn.yml` | A baked ProtonVPN file, with NAT-PMP |
| `examples/rustnet.override.yml` | Optional connection capture. Off unless you add this file |

```bash
docker run --rm ghcr.io/lostinfuture/transmission-openvpn:edge list-providers
```

That list is the set of baked names. A NordVPN country is an ISO code such as `NL`. Empty allows any country. `NORDVPN_PROTOCOL` is `udp` or `tcp`. `NORDVPN_CATEGORY` is the servers group, for example `legacy_p2p`.

PIA uses `OPENVPN_CONFIG` as a region id or name, such as `nl_amsterdam`. Empty selects the first online auto region with port forwarding. When `PIA_TOKEN` is set, it is the port-forward token. When the OpenVPN username is empty, that token is also split into the OpenVPN username and password. When the username and password are both set and `PIA_TOKEN` is empty, the supervisor requests a token and does not send the account password as the token.

Proton sets `PORT_FORWARD=natpmp` when `PORT_FORWARD` is empty. `DISABLE_PORT_UPDATER=true` skips the PIA signature loop and NAT-PMP.

`VPN_CONFIG_SOURCE=github` downloads a contrib tarball. `GITHUB_CONFIG_SOURCE_REVISION` must be a 40-character lowercase commit. A branch name is refused.

## Optional RPC password

```yaml
environment:
  TRANSMISSION_RPC_USERNAME: transmission
  TRANSMISSION_RPC_PASSWORD: ${TRANSMISSION_RPC_PASSWORD}
```

Setting either one turns RPC authentication on. Leave both unset and the port stays open, which is the default. A password that already lives only inside `settings.json` is stored hashed. The supervisor needs `TRANSMISSION_RPC_PASSWORD` in the environment to keep talking to Transmission after that.

`TRANSMISSION_RPC_PORT` overrides `9091`. Publish the same port you set.

## If something feels wrong

- **The container exits before OpenVPN.** The ovpn mount is missing, or `OPENVPN_CONFIG` does not match the file name. `vpn` means `vpn.ovpn` inside the mount.
- **The web UI does not load from another machine.** Publish `9091:9091`. Set `LOCAL_NETWORK` to your LAN prefix so that network uses the original gateway. A prefix shorter than `/8`, including `/0`, is rejected.
- **Docker kills the container around 10 seconds after stop.** Set `stop_grace_period: 45s` (`--stop-timeout 45` on the CLI).
- **`ENABLE_UFW=false` and traffic still cannot bypass the tunnel.** That variable does not disable the kill switch. `ENABLE_KILLSWITCH=false` does, and it logs a warning.
- **A hook did not run.** The file must be owned by root, must not be a symlink, and must not be writable by group or other. Each script is killed after 10 seconds.

## Environment

| Variable | Default | What to set |
| :--- | :--- | :--- |
| `OPENVPN_PROVIDER` | `custom` | `custom`, or a baked name from `list-providers`, or `nordvpn`, or `pia`. |
| `OPENVPN_CONFIG` | `default` | For `custom`, the file name without `.ovpn`. A comma-separated list picks one entry at random. |
| `OPENVPN_USERNAME`, `OPENVPN_PASSWORD` | empty | Provider login. Leave them out of the Compose file. |
| `LOCAL_NETWORK` | empty | LAN prefix, for example `192.168.1.0/24`. Prefixes shorter than `/8` are rejected. |
| `PUID`, `PGID` | `1000` | User and group for Transmission. `0` is root, with a warning. |
| `ENABLE_KILLSWITCH` | `true` | `false` disables the egress drop. |
| `TRANSMISSION_RPC_PORT` | `9091` | Must match the port you publish. |
| `TRANSMISSION_RPC_USERNAME`, `TRANSMISSION_RPC_PASSWORD` | empty | Set both to require a login on the web UI. |
| `TRANSMISSION_WEB_UI` | empty | Empty is the stock UI. `flood-for-transmission` (alias `flood`) or `transmissionic`. |
| `TRANSMISSION_MESSAGE_LEVEL` | Transmission's own default, `4` | `2` is error on the 4.x scale. |
| `PORT_FORWARD` | empty | `natpmp` asks the tun gateway for a port. Proton sets this when it is empty. |
| `PIA_TOKEN` | empty | PIA port-forward token. See the provider section. |
| `NORDVPN_COUNTRY` | empty | ISO code. Empty allows any country. |
| `SELFHEAL` | `false` | `true` restarts OpenVPN in this process. See Recovery. |
| `ENABLE_RUSTNET` | `false` | `true` starts the capture. Any other value exits before OpenVPN. |
| `HEALTH_CHECK_HOST` | empty | With `SELFHEAL=true`, three failed TCP dials to port 443 on this host, bound to the tun address, restart OpenVPN. |
| `VPN_CONFIG_SOURCE` | baked snapshot | `github` downloads a tarball. The revision must be a full commit. |

## Web UI

An empty `TRANSMISSION_WEB_UI` leaves the stock UI. `TRANSMISSION_WEB_HOME`, when set, wins.

`flood-for-transmission` serves `/opt/transmission-ui/flood-for-transmission`. `transmissionic` serves `/opt/transmission-ui/transmissionic` (v1.9.0). `combustion`, `kettu`, `shift`, and `transmission-web-control` exit 1.

## Hooks

Optional POSIX scripts, at fixed paths:

- `/scripts/openvpn-pre-start.sh`
- `/scripts/transmission-pre-start.sh`
- `/scripts/transmission-post-start.sh`
- `/scripts/transmission-pre-stop.sh`
- `/scripts/transmission-post-stop.sh`

A missing file is success. A symlink, a file that is not owned by root, or a file that is writable by group or other is an error. Each script is killed after 10 seconds. They run as root. Their environment does not include passwords, tokens, or other secret variables, and those values are redacted from script output. The Compose file does not mount `/scripts`. The supervisor does not reap a process a hook backgrounds. `init: true` covers that.

## Rustnet

`ENABLE_RUSTNET` defaults to false. On an image without `/usr/bin/rustnet` (armv7), `true` logs once and continues. The supervisor starts it after the kill switch and before OpenVPN, and it does not restart the capture on hook-up or hook-down.

The arguments are `rustnet --headless --output jsonl --interface any --no-resolve-dns --no-geoip --refresh-interval <RUSTNET_REFRESH_MS>`. `RUSTNET_REFRESH_MS` defaults to 5000. A value below 1000, or a value that is not an integer, is a fatal error. Stdout and stderr are prefixed `component=rustnet`, and the JSONL is left intact.

`RUSTNET_PCAP` defaults to empty. When set, it must be an absolute path under `/config`. The supervisor refuses a symlink, creates a regular file mode `0600`, and passes it as `--pcap-export`. If Rustnet exits, the tunnel stays up. The supervisor restarts it with backoff at most five times in ten minutes, then logs an error and leaves it down until the next container start. The healthcheck does not read Rustnet.

`docker exec` can run `rustnet --interface any --no-resolve-dns --no-geoip` for the TUI. That is a second process. The binary has no file capabilities. The image does not build the `kubernetes` Cargo feature. OpenVPN and Rustnet do not inherit password or token variables.

Turn it on with `examples/rustnet.override.yml`. Compose replaces `cap_add`, so that file repeats `NET_ADMIN` and adds `NET_RAW`, `BPF`, and `PERFMON`, plus a read-only `/sys/kernel/btf` mount. The capture can name host processes. kprobes are host-wide.

```bash
docker compose -f docker-compose.yml -f examples/rustnet.override.yml up -d
```

## Recovery

Three separate mechanisms. The root Compose file enables only the first.

- **Docker `restart:`** starts a new container after a crash or a daemon reboot. `docker-compose.yml` sets `unless-stopped`.
- **`willfarrell/autoheal`** restarts containers whose healthcheck fails. The image sets the `autoheal=true` label. The label does nothing unless you run that sidecar.
- **`SELFHEAL=true`** restarts OpenVPN inside this process after three failed probes, or when the tun device loses its address. Transmission stays down until the next hook-up. The restart reuses `/run/openvpn/config.ovpn`. It does not resolve DNS again. An empty `HEALTH_CHECK_HOST` only reacts to the missing address.

## Pull the image

GitHub Container Registry is published from this repo. `edge` moves on `main` and on the Monday rebuild. A version tag such as `v0.1.0` also publishes `0.1.0`, `v0.1.0`, `0.1`, `0`, and `latest`.

```bash
docker pull ghcr.io/lostinfuture/transmission-openvpn:edge
docker pull ghcr.io/lostinfuture/transmission-openvpn:0.1.0
```

Docker Hub uses the same tags when the repository secret `DOCKER_PASSWORD` is set. `DOCKER_USERNAME` defaults to `lostinfuture`.

```bash
docker pull lostinfuture/transmission-openvpn:edge
docker pull lostinfuture/transmission-openvpn:latest
```

Pin the image digest when you want a frozen build. The Monday cron rebuilds `edge` from the same Dockerfile pins.

## Build from source

```bash
docker build -t transmission-openvpn:dev .
```

The context needs `Dockerfile`, `cmd/`, `internal/`, `scripts/`, and `sbom/`. A copy that omits `sbom/` fails on `COPY sbom/rustnet.cdx.json`.

```bash
docker run --rm transmission-openvpn:dev version
docker run --rm transmission-openvpn:dev list-providers
docker run --rm transmission-openvpn:dev check-snapshot
docker run --rm --cap-add=NET_ADMIN transmission-openvpn:dev firewall-selftest
docker run --rm --cap-add=NET_ADMIN transmission-openvpn:dev \
  drop-exec --uid 65534 --gid 65534 --nofile 64 -- cat /proc/self/status
```

A bare `run` with no `.ovpn` exits 1. `firewall-selftest` installs the kill switch in that container and removes it on the way out. `drop-exec` should show `CapBnd` as all zeros. Dropping the bounding set needs `SETPCAP`, which is in Docker's default set and is kept by `--cap-add=NET_ADMIN`.

## Credits and licenses

The Go supervisor in this repository is [Apache-2.0](LICENSE). Copyright 2026 lostinfuture.

The image also contains other programs, on their own terms:

- [Transmission](https://github.com/transmission/transmission) 4.1.4, GPL-2.0-only OR GPL-3.0-only, with the OpenSSL exception in its `COPYING`. Some files are MIT.
- [OpenVPN](https://openvpn.net/) 2.7.8, GPL-2.0-only WITH openvpn-openssl-exception.
- [flood-for-transmission](https://github.com/johman10/flood-for-transmission) v1.0.1, GPL-3.0-only.
- [Transmissionic](https://github.com/lostinfuture/transmissionic) v1.9.0, MIT.
- [Rustnet](https://github.com/domcyrus/rustnet) 1.7.0, Apache-2.0, on amd64 and arm64.
- Provider files from [haugene/vpn-configs-contrib](https://github.com/haugene/vpn-configs-contrib).

The image label `org.opencontainers.image.licenses` is the SPDX combination of those notices. Copies of the upstream license files are under `/usr/share/licenses/` in the image.
