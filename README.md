# PortTripper

A honeypot that binds to a large range of dummy TCP and UDP ports to frustrate network fingerprinting. Attackers running `nmap` or similar tools see thousands of open ports, making it difficult to identify real services.

## How it works

On startup PortTripper:

1. Scans the configured port range and builds a whitelist of ports already in use by real services (first run only).
2. Binds TCP and UDP listeners on every port in the range that is not in the whitelist.
3. On TCP: accepts connections, holds them open for a configurable duration, then drops them, wasting the scanner's threads and file descriptors.
4. On UDP: reads and discards datagrams without replying, so ports appear `open|filtered` to scanners rather than `closed`.

All real service ports are untouched because they are already bound before PortTripper starts, and the auto-generated whitelist tells PortTripper to skip them.

## Requirements

- Go 1.21 or later
- Linux (or any Unix). Running as root or with `CAP_NET_BIND_SERVICE` is required only if `-startport` is below 1024.

## Build

```sh
go build -o PortTripper main.go
```

## Quick start

```sh
# First run: PortTripper scans for bound ports, writes whitelist.txt, then starts.
sudo ./PortTripper

# Subsequent runs: whitelist.txt already exists, scan is skipped.
sudo ./PortTripper
```

On first run you will see:

```
[INFO] first run: scanning for already-bound ports  range=1024-65000
[INFO] first run: whitelist written with currently-bound ports  file=whitelist.txt
[INFO] whitelist loaded  file=whitelist.txt  ports=8
[INFO] all listeners started  bound=127952  skipped=8  failed=0
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-portfile` | `whitelist.txt` | Path to whitelist file |
| `-startport` | `1024` | First (lowest) port to bind |
| `-endport` | `65000` | Last (highest) port to bind |
| `-hold` | `2` | Seconds to hold a TCP connection open before closing |
| `-udp` | `true` | Bind UDP ports in addition to TCP; disable with `-udp=false` |
| `-maxconns` | `10000` | Global cap on simultaneous connections (DoS protection) |
| `-ratelimit` | `5` | Max new connections per second from a single source IP |
| `-metrics` | _(off)_ | Address for Prometheus `/metrics` endpoint, e.g. `:9100` |
| `-jsonlog` | `false` | Emit newline-delimited JSON log lines instead of plain text |
| `-verbose` | `false` | Print debug-level log lines (bind failures, skipped ports, etc.) |

```sh
# Example: cover ports 1024–65000, hold connections for 5 s, export metrics
sudo ./PortTripper -hold 5 -metrics :9100

# Disable UDP if you need to conserve file descriptors
sudo ./PortTripper -udp=false

# Use a custom whitelist path
sudo ./PortTripper -portfile /etc/PortTripper/whitelist.txt
```

## Whitelist file

`whitelist.txt` is created automatically on first run by probing which ports are already bound. Every port that cannot be bound (already in use, permission denied, etc.) is added to the list so PortTripper never fights with real services.

You can edit the file freely at any time. Restart PortTripper for changes to take effect.

```
# PortTripper – port whitelist (auto-generated on first run)
# Ports below were already bound by other processes at startup.
# Edit freely: lines starting with '#' and blank lines are ignored.

22
80
443
5432
```

To regenerate the whitelist from scratch, delete the file and restart PortTripper.

## Logging

### Plain text (default)

```
2026-01-15T09:12:03Z [INFO] connection src=203.0.113.42 port=4444 proto=tcp
2026-01-15T09:12:05Z [WARN] rate limit exceeded src=203.0.113.42 port=9999
```

### JSON (`-jsonlog`)

```json
{"level":"INFO","msg":"connection","port":4444,"proto":"tcp","src":"203.0.113.42","ts":"2026-01-15T09:12:03.112Z"}
{"level":"WARN","msg":"rate limit exceeded","port":9999,"src":"203.0.113.42","ts":"2026-01-15T09:12:05.004Z"}
```

JSON output is designed to drop directly into Splunk, Loki, Datadog, or any SIEM that ingests newline-delimited JSON.

## Prometheus metrics

Start with `-metrics :9100` to expose a `/metrics` endpoint in Prometheus text format:

```
PortTripper_connections_total 48291
PortTripper_connections_rejected_total 312
PortTripper_connections_active 7
PortTripper_ports_bound 127952
PortTripper_ports_failed 0
PortTripper_ports_skipped 8
```

A useful alert to add in Alertmanager:

```yaml
- alert: PortTripperScanSpike
  expr: rate(PortTripper_connections_total[1m]) > 500
  for: 30s
  annotations:
    summary: "High connection rate on honeypot ports, possible active scan!"
```

## Resource usage

Binding ~64 000 ports creates roughly 128 000 goroutines at steady state (one accept loop + one shutdown watcher per listener). On a typical Linux server this uses around 150–250 MB of RSS. The global connection cap (`-maxconns`) prevents memory growth under a flood.

To check the fd limit before deploying:

```sh
ulimit -n                   # soft limit (usually 1024 for interactive shells)
cat /proc/sys/fs/file-max   # system-wide hard limit
```

For production, raise the limit before starting PortTripper:

```sh
ulimit -n 262144
```

## Security considerations

- PortTripper is a deception tool, not a firewall. Use it alongside `iptables`/`nftables` and proper network segmentation, not instead of them.
- The `-ratelimit` flag limits new connections per second per source IP. Tune it based on expected legitimate traffic patterns.
- Log lines include source IPs. Feed them into a SIEM or fail2ban to act on scanner IPs automatically.
- Do not run PortTripper on the same port as any real service. If in doubt, check `ss -tlnp` before adjusting the whitelist.

## License

Distributed under the **Apache 2.0 License**, see [`LICENSE`](LICENSE) for full terms.