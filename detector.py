#!/usr/bin/env python3
"""
DDos Detector - passive flood detection for Linux.

Samples kernel counters and TCP state tables from /proc, computes rates
and flags anomalies typical of flooding attacks:

  - throughput spike per interface (packets/s, bytes/s, drops)
  - SYN_RECV explosion                      (SYN flood)
  - ESTABLISHED / total connection explosion (connection flood)
  - large number of distinct source IPs     (distributed attack)
  - high new-connection rate

Two output modes:
  * live dashboard  - full-screen terminal UI (default)
  * log mode        - plain timestamped lines, fit for daemons/logs

Standard library only. Linux only.
"""

import argparse
import json
import logging
import os
import shutil
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

PROC_NET_DEV = Path("/proc/net/dev")
PROC_NET_TCP = Path("/proc/net/tcp")
PROC_NET_UDP = Path("/proc/net/udp")

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

LOG_STATES = ("SYN_RECV", "ESTABLISHED", "TIME_WAIT", "SYN_SENT", "FIN_WAIT1",
              "FIN_WAIT2", "CLOSE_WAIT", "LAST_ACK", "CLOSING")

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[90m"
CLEAR = "\033[2J\033[H"
ERASE = "\033[K"

log = logging.getLogger("ddos")


def colored(text, color):
    return f"{color}{text}{RESET}" if sys.stdout.isatty() else text


# ---------------------------------------------------------------------------
# /proc readers
# ---------------------------------------------------------------------------

def read_dev():
    data = {}
    try:
        with PROC_NET_DEV.open() as f:
            f.readline()
            f.readline()
            for line in f:
                iface, rest = line.split(":", 1)
                iface = iface.strip()
                if iface.startswith(("lo", "veth", "br-", "docker", "tun", "virbr")):
                    continue
                fields = rest.split()
                data[iface] = {
                    "rx_bytes": int(fields[0]),
                    "rx_packets": int(fields[1]),
                    "rx_drop": int(fields[3]),
                    "tx_bytes": int(fields[8]),
                    "tx_packets": int(fields[9]),
                }
    except (FileNotFoundError, PermissionError) as e:
        log.error("cannot read %s: %s", PROC_NET_DEV, e)
    return data


def read_tcp_states(path):
    states = defaultdict(int)
    sources = set()
    try:
        with path.open(errors="ignore") as f:
            f.readline()
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                state = TCP_STATES.get(parts[3], parts[3])
                states[state] += 1
                remote = parts[2].split(":")
                if (len(remote) == 2
                        and remote[0] not in ("00000000",
                                              "00000000000000000000000000000000")):
                    sources.add(remote[0])
    except (FileNotFoundError, PermissionError) as e:
        log.error("cannot read %s: %s", path, e)
    return states, sources


def read_udp_sources(path):
    sources = set()
    try:
        with path.open(errors="ignore") as f:
            f.readline()
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    remote = parts[2].split(":")
                    if len(remote) == 2 and remote[0] != "00000000":
                        sources.add(remote[0])
    except (FileNotFoundError, PermissionError) as e:
        log.error("cannot read %s: %s", path, e)
    return sources


def human_bytes(n):
    units = ("B", "KB", "MB", "GB")
    for u in units:
        if n < 1024 or u == units[-1]:
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} {u}"
        n /= 1024


def human_num(n):
    for u in ("", "K", "M"):
        if n < 1000 or u == "M":
            return f"{n:.0f}{u}" if u == "" else f"{n:.1f}{u}"
        n /= 1000


# ---------------------------------------------------------------------------
# detector
# ---------------------------------------------------------------------------

class Detector:
    def __init__(self, iface=None, pkt_thr=20000, byte_thr=50_000_000,
                 syn_thr=500, conn_thr=30000, src_thr=1000, newconn_thr=2000,
                 interval=1.0, json_out=None):
        self.iface = iface
        self.pkt_thr = pkt_thr
        self.byte_thr = byte_thr
        self.syn_thr = syn_thr
        self.conn_thr = conn_thr
        self.src_thr = src_thr
        self.newconn_thr = newconn_thr
        self.interval = interval
        self.json_out = json_out
        self.prev = None
        self.alerts = deque(maxlen=8)
        self.attack_since = None
        self.render = render_dashboard

    def snapshot(self):
        dev = read_dev()
        tcp_states, tcp_src = read_tcp_states(PROC_NET_TCP)
        udp_src = read_udp_sources(PROC_NET_UDP)
        total = sum(v for k, v in tcp_states.items() if k in LOG_STATES)
        return {
            "ts": time.time(),
            "dev": dev,
            "states": tcp_states,
            "tcp_src": len(tcp_src),
            "udp_src": len(udp_src),
            "src_total": len(tcp_src | udp_src),
            "connections": total,
        }

    @staticmethod
    def _rate(now, old_ts, old_val, new_val):
        dt = now - old_ts
        if dt <= 0:
            return 0.0
        return (new_val - old_val) / dt

    def analyze(self, cur):
        if self.prev is None:
            return {}
        findings = {}
        for iface, c in cur["dev"].items():
            if self.iface and iface != self.iface:
                continue
            p = self.prev["dev"].get(iface)
            if p is None:
                continue
            rx_pkt = self._rate(cur["ts"], self.prev["ts"], p["rx_packets"], c["rx_packets"])
            tx_pkt = self._rate(cur["ts"], self.prev["ts"], p["tx_packets"], c["tx_packets"])
            rx_byte = self._rate(cur["ts"], self.prev["ts"], p["rx_bytes"], c["rx_bytes"])
            tx_byte = self._rate(cur["ts"], self.prev["ts"], p["tx_bytes"], c["tx_bytes"])
            drop = self._rate(cur["ts"], self.prev["ts"], p["rx_drop"], c["rx_drop"])
            total_pkt = rx_pkt + tx_pkt
            total_byte = rx_byte + tx_byte
            if total_pkt > self.pkt_thr or total_byte > self.byte_thr:
                findings["traffic"] = {
                    "iface": iface, "pkt_s": round(total_pkt, 1),
                    "bytes_s": round(total_byte, 1), "rx_drop_s": round(drop, 1),
                }
        states = cur["states"]
        if states.get("SYN_RECV", 0) > self.syn_thr:
            findings["syn_flood"] = {"syn_recv": states["SYN_RECV"]}
        if cur["connections"] > self.conn_thr:
            findings["conn_flood"] = {"connections": cur["connections"]}
        if cur["src_total"] > self.src_thr:
            findings["distributed"] = {"src_ips": cur["src_total"],
                                       "tcp_src": cur["tcp_src"],
                                       "udp_src": cur["udp_src"]}
        new_conn = cur["connections"] - self.prev["connections"]
        if new_conn / self.interval > self.newconn_thr:
            findings["conn_rate"] = {"new_conn_s": round(new_conn / self.interval, 1)}
        return findings

    def _emit(self, kind, info):
        entry = {"ts": self.attack_since or self.prev["ts"], "kind": kind, **info}
        if self.json_out:
            self.json_out.write(json.dumps(entry) + "\n")
            self.json_out.flush()
        self.alerts.appendleft(entry)
        log.warning("ALERT %s: %s", kind.upper(), json.dumps(info))

    def run(self):
        if not self.prev:
            self.prev = self.snapshot()
        while True:
            cur = self.snapshot()
            findings = self.analyze(cur)
            if findings:
                if self.attack_since is None:
                    self.attack_since = cur["ts"]
                for kind, info in findings.items():
                    self._emit(kind, info)
            else:
                self.attack_since = None
            self._render(cur, findings)
            self.prev = cur
            time.sleep(self.interval)

    def _render(self, cur, findings):
        self.render(self, cur, findings)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _align(text, width):
    text = str(text)
    return text[:width].ljust(width)


def render_dashboard(d, cur, findings):
    columns, _ = shutil.get_terminal_size((100, 24))
    lines = [f"{BOLD}DDoS DETECTOR{RESET} "
             f"{DIM}sampling every {d.interval}s | thresholds: "
             f"pkt/s>{human_num(d.pkt_thr)} bytes/s>{human_num(d.byte_thr)} "
             f"syn>{d.syn_thr} conn>{human_num(d.conn_thr)} "
             f"src>{d.src_thr} new/s>{human_num(d.newconn_thr)}{RESET}"]

    under_attack = bool(findings)
    status = (f"{RED}{BOLD}UNDER ATTACK{RESET}"
              if under_attack else f"{GREEN}NORMAL{RESET}")
    lines.append(f"status: {status}   "
                 f"{DIM}press Ctrl-C to stop{RESET}\n")

    if not cur["dev"]:
        lines.append(f"{RED}no monitored interfaces{RESET}")
    else:
        lines.append(f"{BOLD}{_align('interface', 12)} {_align('rx pkt/s', 10)} "
                     f"{_align('tx pkt/s', 10)} {_align('rx/s', 9)} {_align('tx/s', 9)} "
                     f"{_align('drop/s', 9)}{RESET}")
        for iface, c in cur["dev"].items():
            if d.iface and iface != d.iface:
                continue
            p = d.prev["dev"].get(iface)
            rx_pkt = tx_pkt = rx_byte = tx_byte = drop = 0.0
            if p:
                rx_pkt = d._rate(cur["ts"], d.prev["ts"], p["rx_packets"], c["rx_packets"])
                tx_pkt = d._rate(cur["ts"], d.prev["ts"], p["tx_packets"], c["tx_packets"])
                rx_byte = d._rate(cur["ts"], d.prev["ts"], p["rx_bytes"], c["rx_bytes"])
                tx_byte = d._rate(cur["ts"], d.prev["ts"], p["tx_bytes"], c["tx_bytes"])
                drop = d._rate(cur["ts"], d.prev["ts"], p["rx_drop"], c["rx_drop"])
            hit = rx_pkt + tx_pkt > d.pkt_thr or rx_byte + tx_byte > d.byte_thr
            color = RED if hit else ""
            line = (f"{_align(iface, 12)} {_align(human_num(rx_pkt), 10)} "
                    f"{_align(human_num(tx_pkt), 10)} {_align(human_bytes(rx_byte), 9)} "
                    f"{_align(human_bytes(tx_byte), 9)} {_align(human_num(drop), 9)}")
            lines.append(colored(line, color))

    lines.append("")
    lines.append(f"{BOLD}{_align('tcp state', 14)} {_align('count', 8)}  note{RESET}")
    for state in LOG_STATES + ("LISTEN",):
        count = cur["states"].get(state, 0)
        note = ""
        color = ""
        if state == "SYN_RECV" and count > d.syn_thr:
            color, note = RED, f"  {BOLD}SYN flood{RESET}"
        lines.append(colored(
            f"{_align(state, 14)} {_align(human_num(count), 8)} {note}", color))

    lines.append("")
    lines.append(f"{_align('connections', 14)} {human_num(cur['connections'])}")
    lines.append(f"{_align('new conn/s', 14)} {human_num((cur['connections'] - d.prev['connections']) / d.interval)}")
    lines.append(f"{_align('distinct src ip', 14)} {cur['src_total']} "
                 f"({cur['tcp_src']} tcp / {cur['udp_src']} udp)")

    if d.alerts:
        lines.append("")
        lines.append(f"{BOLD}{RED}recent alerts{RESET}")
        for a in list(d.alerts)[:4]:
            ts = time.strftime("%H:%M:%S", time.localtime(a["ts"]))
            lines.append(f"  {DIM}{ts}{RESET} {RED}{BOLD}{a['kind']}{RESET} {json.dumps(a, default=str)}")

    width = min(columns, 110)
    body = "\n".join(lines)
    if sys.stdout.isatty():
        sys.stdout.write(CLEAR + body + ERASE + "\n")
    else:
        sys.stdout.write(body + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DDoS Detector - passive flood detection for Linux")
    parser.add_argument("-i", "--iface", help="monitor only this interface")
    parser.add_argument("--pkt-thr", type=int, default=20000,
                        help="packets/s alert threshold (default 20000)")
    parser.add_argument("--byte-thr", type=int, default=50_000_000,
                        help="bytes/s alert threshold (default 50 MB/s)")
    parser.add_argument("--syn-thr", type=int, default=500,
                        help="SYN_RECV socket threshold (default 500)")
    parser.add_argument("--conn-thr", type=int, default=30000,
                        help="total connection threshold (default 30000)")
    parser.add_argument("--src-thr", type=int, default=1000,
                        help="distinct source IP threshold (default 1000)")
    parser.add_argument("--newconn-thr", type=int, default=2000,
                        help="new connections/s threshold (default 2000)")
    parser.add_argument("-t", "--interval", type=float, default=1.0,
                        help="sampling interval in seconds (default 1.0)")
    parser.add_argument("-o", "--out", metavar="FILE",
                        help="append alerts as JSON lines to FILE")
    parser.add_argument("--no-dashboard", action="store_true",
                        help="plain log output, no dashboard redraw "
                             "(for systemd / daemons)")
    args = parser.parse_args()

    if sys.stdout.isatty() and not args.no_dashboard:
        logging.basicConfig(level=logging.WARNING,
                            format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
    else:
        logging.basicConfig(level=logging.INFO,
                            format="[%(asctime)s] %(levelname)s: %(message)s",
                            datefmt="%H:%M:%S")

    out = open(args.out, "a") if args.out else None
    d = Detector(iface=args.iface, pkt_thr=args.pkt_thr, byte_thr=args.byte_thr,
                 syn_thr=args.syn_thr, conn_thr=args.conn_thr,
                 src_thr=args.src_thr, newconn_thr=args.newconn_thr,
                 interval=args.interval, json_out=out)
    try:
        log.info("DDoS detector started (interval=%ss)", args.interval)
        if not sys.stdout.isatty() or args.no_dashboard:
            d.render = lambda self, cur, findings: None
        d.run()
    except KeyboardInterrupt:
        print()
        log.info("stopped")
    finally:
        if out:
            out.close()


if __name__ == "__main__":
    main()
