# DDos Detector

Passive flood detection for Linux. It samples kernel counters and TCP state
tables from `/proc`, computes rates, and flags anomalies that are typical of
flooding attacks — no dependencies beyond the Python standard library, no
root privileges required for basic operation.

The detector does not block anything. It watches, reports and lets you
decide. Run it on the box under attack, or on a mirrored port of the
gateway.

---

## What it detects

| Finding       | Signal used                                        | Typical cause        |
|---------------|----------------------------------------------------|----------------------|
| `traffic`     | packets/s and bytes/s per interface, rx drops      | volumetric flood     |
| `syn_flood`   | sockets stuck in `SYN_RECV`                        | SYN flood            |
| `conn_flood`  | total established/in-flight TCP sockets            | connection flood     |
| `distributed` | number of distinct source IPs (TCP + UDP)          | botnet / reflection  |
| `conn_rate`   | new connections appearing per second               | connection rate flood|

All thresholds are configurable, because "normal" looks different on a
desktop and on a busy server.

---

## Installation

```bash
git clone https://github.com/0bcu/DDos-Detector.git
cd DDos-Detector
```

No `pip install`. Python 3.6+ is enough.

---

## Usage

### Live dashboard (default)

```bash
python3 detector.py
```

Full-screen terminal UI, refreshed every second:

```
DDoS DETECTOR  sampling every 1.0s | thresholds: pkt/s>20K bytes/s>50.0M syn>500 conn>30.0K src>1.0K new/s>2.0K
status: NORMAL   press Ctrl-C to stop

interface    rx pkt/s    tx pkt/s    rx/s       tx/s       drop/s
eth0         1240.2      908.7       2.1 MB     812.4 KB   0

tcp state    count    note
LISTEN       12
SYN_RECV     3
ESTABLISHED  87
TIME_WAIT    141

connections  231
new conn/s   14.2
distinct src ip  9 (8 tcp / 1 udp)
```

When a threshold is crossed, the status flips to **UNDER ATTACK**, the
offending rows turn red, and the alert is listed in a `recent alerts`
section:

```
status: UNDER ATTACK   press Ctrl-C to stop

tcp state    count    note
SYN_RECV     6240     SYN flood

recent alerts
  23:58:11  syn_flood  {"syn_recv": 6240}
```

### Monitor one interface

```bash
python3 detector.py -i eth0
```

### Lower or raise thresholds

```bash
# sensitive: anything above 5k pkt/s or 300 half-open sockets
python3 detector.py --pkt-thr 5000 --syn-thr 300

# relaxed: busy server
python3 detector.py --pkt-thr 500000 --conn-thr 200000 --newconn-thr 5000
```

### Log mode (systemd, cron, daemons)

No dashboard redraw — plain timestamped lines, safe to redirect:

```bash
python3 detector.py --no-dashboard -t 2 | tee -a ddos.log
```

### Persistent alert log (JSON lines)

Every alert is appended to the file as one JSON object per line, ready for
parsing or feeding into a SIEM:

```bash
python3 detector.py -o alerts.jsonl
```

Example alert line:

```json
{"ts": 1783419842, "kind": "syn_flood", "syn_recv": 6240}
```

Alert kinds: `traffic`, `syn_flood`, `conn_flood`, `distributed`,
`conn_rate`.

---

## Options

| Flag                | Default     | Meaning                                   |
|---------------------|-------------|-------------------------------------------|
| `-i, --iface`       | all         | monitor only this interface               |
| `--pkt-thr`         | 20000       | packets/s threshold                       |
| `--byte-thr`        | 50000000    | bytes/s threshold (50 MB/s)               |
| `--syn-thr`         | 500         | `SYN_RECV` sockets threshold              |
| `--conn-thr`        | 30000       | total connections threshold               |
| `--src-thr`         | 1000        | distinct source IPs threshold             |
| `--newconn-thr`     | 2000        | new connections/s threshold               |
| `-t, --interval`    | 1.0         | sampling interval in seconds              |
| `-o, --out FILE`    | -           | append alerts as JSON lines to FILE       |
| `--no-dashboard`    | off         | plain log output, no screen redraw        |

---

## How it works

Every interval the detector reads three kernel interfaces:

- `/proc/net/dev` — per-interface packet/byte/drop counters
- `/proc/net/tcp` — TCP socket table with connection states
- `/proc/net/udp` — UDP socket table, used for source counting

Rates are computed between consecutive samples, so it is immune to counter
wraparound and requires no daemonization: kill it and the box is untouched.
Sending `Ctrl-C` stops it cleanly.

Notes:

- Interfaces that are virtual (`lo`, `veth*`, `br-*`, `docker*`, `tun*`,
  `virbr*`) are skipped by default.
- Reading the TCP state table is fast even with thousands of sockets; a
  busy server may want `-t 2` to reduce sampling cost.
- For full packet-level analysis (payloads, flags, spoofed sources), pair
  it with `tcpdump` on the gateway's mirrored port.

---

## License

MIT
