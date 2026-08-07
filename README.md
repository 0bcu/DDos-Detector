<div align="center">

```
  /$$$$$$  /$$
 /$$$_  $$| $$
| $$$$\ $$| $$$$$$$   /$$$$$$$ /$$   /$$
| $$ $$ $$| $$__  $$ /$$_____/| $$  | $$
| $$\ $$$$| $$  \ $$| $$      | $$  | $$
| $$ \ $$$| $$  | $$| $$      | $$  | $$
|  $$$$$$/| $$$$$$$/|  $$$$$$$|  $$$$$$/
 \______/ |_______/  \_______/ \______/
```

# DDos Detector

Passive flood detection for Linux — no dependencies, no root required.

</div>

---

## What it is

`DDos Detector` samples kernel counters and TCP state tables from `/proc`,
computes rates between samples, and flags the anomalies that show up when a
flooding attack is in progress:

- throughput spikes per interface (packets/s, bytes/s, drops)
- `SYN_RECV` explosion (SYN flood)
- connection count explosion (connection flood)
- large numbers of distinct source IPs (distributed attack)
- high new-connection rate

It is **passive**: it never sends traffic, never blocks anything, and never
changes system state. Kill it and the machine is exactly as it was.

## Requirements

| Requirement | Detail                                   |
|-------------|------------------------------------------|
| OS          | Linux (reads `/proc/net/*`)              |
| Python      | 3.6+ (standard library only)             |
| Root        | not required                             |

---

## Quick start

```bash
git clone https://github.com/0bcu/DDos-Detector.git
cd DDos-Detector

python3 detector.py
```

That's it. A live dashboard opens in the terminal, refreshed every second.
Press `Ctrl-C` to exit — the terminal is restored exactly as it was.

## Interface

```
┌──────────────────────────────────────────────────────────────────────┐
│    /$$$$$$  /$$                                                      │
│   /$$$_  $$| $$                                                      │
│  | $$$$\ $$| $$$$$$$   /$$$$$$$ /$$   /$$                            │
│  | $$ $$ $$| $$__  $$ /$$_____/| $$  | $$                            │
│  | $$\ $$$$| $$  \ $$| $$      | $$  | $$                            │
│  | $$ \ $$$| $$  | $$| $$      | $$  | $$                            │
│  |  $$$$$$/| $$$$$$$/|  $$$$$$$|  $$$$$$/                            │
│   \______/ |_______/  \_______/ \______/                             │
│ D D o S   D E T E C T O R           v1.1                             │
│ github.com/0bcu/DDos-Detector       sampling every 1.0s              │
├──────────────────────────────────────────────────────────────────────┤
│ ● NORMAL      connections   231                                      │
│ new conn/s    14.2                                                    │
│ distinct src ip  9 (8 tcp / 1 udp)                                    │
├──────────────────────────────────────────────────────────────────────┤
│ interface      rx pkt/s   tx pkt/s   rx/s      tx/s      drop/s      │
│ eth0  ██░░░░░░  1240.1    908.7      2.1 MB    812.4 KB  0           │
├──────────────────────────────────────────────────────────────────────┤
│ tcp state      count      note                                       │
│ SYN_RECV       6240       ⚠ SYN flood                                │
│ ESTABLISHED    87                                                     │
├──────────────────────────────────────────────────────────────────────┤
│ recent alerts                                                         │
│  23:58:11  SYN_FLOOD    {"syn_recv": 6240}                            │
├──────────────────────────────────────────────────────────────────────┤
│ thr: pkt/s>20.0K byt/s>50.0M syn>500 conn>30.0K  github.com/0bcu/DDos-Detector │
└──────────────────────────────────────────────────────────────────────┘
```

The UI runs in the terminal's **alternate screen buffer** (the same
technique htop and btop use):

- a single stable frame is redrawn in place — scrolling the wheel never
  produces duplicated frames
- neutral gray/white palette; red and green are reserved for status
- the header banner is hidden automatically on narrow terminals
  (< 80 columns) so the layout never breaks

Sections:

| Section      | Shows                                                     |
|--------------|-----------------------------------------------------------|
| Status       | NORMAL / UNDER ATTACK, total connections, new conn/s, distinct source IPs |
| Interfaces   | per-interface rx/tx packets and bytes per second, drops, utilization gauge |
| TCP states   | socket count per state, with `⚠ SYN flood` marker         |
| Alerts       | last alerts with timestamp and JSON payload               |
| Footer       | active thresholds, project link, quit hint                |

---

## Detection

| Finding       | Signal                                        | Typical cause       |
|---------------|-----------------------------------------------|---------------------|
| `traffic`     | packets/s or bytes/s over threshold, rx drops | volumetric flood    |
| `syn_flood`   | sockets stuck in `SYN_RECV`                   | SYN flood           |
| `conn_flood`  | total connections over threshold              | connection flood    |
| `distributed` | distinct source IPs over threshold            | botnet / reflection |
| `conn_rate`   | new connections per second over threshold     | rate flood          |

Every signal has its own threshold; when any of them fires, an alert is
logged and the status flips to **UNDER ATTACK** until the metric drops back
below the threshold.

---

## Commands

### Monitor everything

```bash
python3 detector.py
```

### Monitor a single interface

```bash
python3 detector.py -i eth0
```

### Tune the detection thresholds

```bash
# sensitive profile - catches floods early
python3 detector.py --pkt-thr 5000 --syn-thr 300 --newconn-thr 500

# relaxed profile - busy server under constant load
python3 detector.py --pkt-thr 500000 --conn-thr 200000 --newconn-thr 5000
```

### Faster / slower sampling

```bash
python3 detector.py -t 0.5      # twice per second
python3 detector.py -t 5        # one sample every 5 seconds
```

### Save alerts to a JSON log

```bash
python3 detector.py -o alerts.jsonl
```

Each alert is one JSON object per line:

```json
{"ts": 1783419842, "kind": "syn_flood", "syn_recv": 6240}
```

### Run without the dashboard (systemd, cron, pipes)

```bash
python3 detector.py --no-dashboard -t 2 | tee -a ddos.log
```

Plain timestamped log lines, safe to redirect or pipe.

---

## Options

| Flag             | Default    | Meaning                                   |
|------------------|------------|-------------------------------------------|
| `-i, --iface`    | all        | monitor only this interface               |
| `--pkt-thr`      | 20000      | packets/s threshold                       |
| `--byte-thr`     | 50000000   | bytes/s threshold (50 MB/s)               |
| `--syn-thr`      | 500        | `SYN_RECV` sockets threshold              |
| `--conn-thr`     | 30000      | total connections threshold               |
| `--src-thr`      | 1000       | distinct source IPs threshold             |
| `--newconn-thr`  | 2000       | new connections/s threshold               |
| `-t, --interval` | 1.0        | sampling interval in seconds              |
| `-o, --out FILE` | -          | append alerts as JSON lines to FILE       |
| `--no-dashboard` | off        | plain log output, no screen redraw        |

---

## How it works

Every interval the detector reads three kernel interfaces:

| File              | Provides                                              |
|-------------------|-------------------------------------------------------|
| `/proc/net/dev`   | per-interface packet/byte/drop counters               |
| `/proc/net/tcp`   | TCP socket table with connection states               |
| `/proc/net/udp`   | UDP socket table, used for source counting            |

Rates are computed between consecutive samples, which makes the detector
immune to counter wraparound. Reading the TCP state table is fast even with
thousands of sockets; on a busy server, use `-t 2` to lower the sampling
cost.

Notes:

- virtual interfaces (`lo`, `veth*`, `br-*`, `docker*`, `tun*`,
  `virbr*`) are skipped by default
- for packet-level analysis (payloads, flags, spoofed sources), pair it
  with `tcpdump` on a mirrored port

---

## License

MIT
