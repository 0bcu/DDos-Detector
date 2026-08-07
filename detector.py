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
import re
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
DIM = "\033[90m"
HOME = "\033[H"
ERASE_DOWN = "\033[J"
ALT_ENTER = "\033[?1049h"
ALT_EXIT = "\033[?1049l"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"

log = logging.getLogger("ddos")


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
# rendering - advanced terminal UI
# ---------------------------------------------------------------------------

VERSION = "1.1"
GITHUB = "github.com/0bcu/DDos-Detector"

BANNER = [
    "  /$$$$$$  /$$                           ",
    " /$$$_  $$| $$                           ",
    "| $$$$\\ $$| $$$$$$$   /$$$$$$$ /$$   /$$",
    "| $$ $$ $$| $$__  $$ /$$_____/| $$  | $$",
    "| $$\\ $$$$| $$  \\ $$| $$      | $$  | $$",
    "| $$ \\ $$$| $$  | $$| $$      | $$  | $$",
    "|  $$$$$$/| $$$$$$$/|  $$$$$$$|  $$$$$$/",
    " \\______/ |_______/  \\_______/ \\______/",
]

TL, TR, BL, BR = "\u250c", "\u2510", "\u2514", "\u2518"
H, V = "\u2500", "\u2502"
TEE_L, TEE_R, TEE_U = "\u251c", "\u2524", "\u252c"
FILL, EMPTY = "\u2588", "\u2591"

CYAN_B = DIM
ACCENT = BOLD


def _align(text, width):
    text = str(text)
    return text[:width].ljust(width)


def _top_line(title, width, accent=None):
    title = f" {title} " if title else ""
    left = (width - len(_visible(title)) - 2) // 2
    right = width - len(_visible(title)) - 2 - left
    c = accent or CYAN_B
    return f"{c}{TL}{H * left}{RESET}{c}{BOLD}{title}{RESET}{c}{H * right}{TR}{RESET}"


def _mid_line(width, accent=None):
    c = accent or CYAN_B
    return f"{c}{TEE_L}{H * (width - 2)}{TEE_R}{RESET}"


def _bot_line(width, accent=None):
    c = accent or CYAN_B
    return f"{c}{BL}{H * (width - 2)}{BR}{RESET}"


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _visible(text):
    return ANSI_RE.sub("", text)


def _row(content, width):
    pad = width - 2 - len(_visible(content))
    if pad < 0:
        pad = 0
    return f"{V}{content}{' ' * pad}{V}"


def _gauge(value, max_value, width=14):
    max_value = max(max_value, 1)
    filled = int((value / max_value) * width)
    filled = max(0, min(width, filled))
    over = value > max_value
    color = RED if over else (YELLOW if filled >= width * 0.7 else "")
    bar = f"{color}{FILL * filled}{RESET}{DIM}{EMPTY * (width - filled)}{RESET}"
    return bar


def render_dashboard(d, cur, findings):
    columns, _ = shutil.get_terminal_size((100, 24))
    width = max(80, min(columns, 110))
    lines = []

    # -------------------------------------------------------------- header
    lines.append(_top_line("", width))
    if width >= 80:
        for art in BANNER:
            lines.append(_row(f"{DIM}  {art.rstrip()}{RESET}", width))
    lines.append(_row(f"{BOLD}{_align('D D o S   D E T E C T O R', 36)}{RESET}"
                      f"{DIM}v{VERSION}{RESET}", width))
    lines.append(_row(f"{DIM}{_align(GITHUB, 36)}{RESET}"
                      f"{_align('sampling every ' + str(d.interval) + 's', 20)}", width))

    # --------------------------------------------------------------- status
    under_attack = bool(findings)
    status = (f"{RED}{BOLD}\u25cf UNDER ATTACK{RESET}"
              if under_attack else f"{GREEN}{BOLD}\u25cf NORMAL{RESET}")
    new_conn = ((cur["connections"] - d.prev["connections"]) / d.interval)
    lines.append(_mid_line(width))
    lines.append(_row(f" {_align(status, 26)}"
                      f"{DIM}{_align('connections', 13)}{RESET}{_align(human_num(cur['connections']), 10)}", width))
    lines.append(_row(f" {DIM}{_align('new conn/s', 26)}{RESET}{_align(human_num(new_conn), 12)}", width))
    lines.append(_row(f" {DIM}{_align('distinct src ip', 26)}{RESET}"
                      f"{_align(cur['src_total'], 12)}{DIM}({cur['tcp_src']} tcp / {cur['udp_src']} udp){RESET}", width))

    # ------------------------------------------------------------ interfaces
    lines.append(_mid_line(width))
    head = (f"{CYAN_B}{BOLD}{_align('interface', 14)}{RESET}"
            f"{DIM}{_align('rx pkt/s', 9)} {_align('tx pkt/s', 9)} "
            f"{_align('rx/s', 9)} {_align('tx/s', 9)} {_align('drop/s', 8)}{RESET}")
    lines.append(_row(head, width))
    if not cur["dev"]:
        lines.append(_row(f"{RED}no monitored interfaces{RESET}", width))
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
        name = _align(iface, 14)
        gauge = _gauge(rx_pkt + tx_pkt, d.pkt_thr, 10)
        if hit:
            name = f"{RED}{BOLD}{_align(iface, 14)}{RESET}"
            rx_pkt_s = f"{RED}{BOLD}{_align(human_num(rx_pkt), 9)}{RESET}"
            tx_pkt_s = f"{RED}{BOLD}{_align(human_num(tx_pkt), 9)}{RESET}"
            rx_b_s = f"{RED}{BOLD}{_align(human_bytes(rx_byte), 9)}{RESET}"
            tx_b_s = f"{RED}{BOLD}{_align(human_bytes(tx_byte), 9)}{RESET}"
        else:
            rx_pkt_s = tx_pkt_s = rx_b_s = tx_b_s = ""
            rx_pkt_s = f"{DIM}{_align(human_num(rx_pkt), 9)}{RESET} "
            tx_pkt_s = f"{_align(human_num(tx_pkt), 9)} "
            rx_b_s = f"{_align(human_bytes(rx_byte), 9)} "
            tx_b_s = f"{_align(human_bytes(tx_byte), 9)} "
        line = (f" {name} {gauge} "
                f"{rx_pkt_s}{tx_pkt_s}{rx_b_s}{tx_b_s}"
                f"{_align(human_num(drop), 8)}")
        lines.append(_row(line, width))

    # ------------------------------------------------------------ tcp states
    lines.append(_mid_line(width))
    head = (f"{CYAN_B}{BOLD}{_align('tcp state', 16)}{RESET}"
            f"{DIM}{_align('count', 9)}  note{RESET}")
    lines.append(_row(head, width))
    for state in LOG_STATES + ("LISTEN",):
        count = cur["states"].get(state, 0)
        note = ""
        color = ""
        if state == "SYN_RECV" and count > d.syn_thr:
            color = RED
            note = f"{RED}{BOLD}\u26a0 SYN flood{RESET}"
        line = (f"{color}{_align(state, 16)}{RESET} "
                f"{_align(human_num(count), 9)}  {note}")
        lines.append(_row(line, width))

    # ---------------------------------------------------------------- alerts
    lines.append(_mid_line(width))
    if d.alerts:
        lines.append(_row(f"{RED}{BOLD}  recent alerts{RESET}", width))
        for a in list(d.alerts)[:4]:
            ts = time.strftime("%H:%M:%S", time.localtime(a["ts"]))
            entry = (f"  {DIM}{ts}{RESET} {RED}{BOLD}{_align(a['kind'].upper(), 12)}{RESET}"
                     f"{DIM}{json.dumps({k: v for k, v in a.items() if k not in ('ts', 'kind')}, default=str)}{RESET}")
            lines.append(_row(entry, width))
    else:
        lines.append(_row(f"{DIM}  no alerts{RESET}", width))

    # ---------------------------------------------------------------- footer
    thr_segs = [
        f"{DIM}pkt/s>{human_num(d.pkt_thr)}{RESET}",
        f"{DIM}byt/s>{human_num(d.byte_thr)}{RESET}",
        f"{DIM}syn>{d.syn_thr}{RESET}",
        f"{DIM}conn>{human_num(d.conn_thr)}{RESET}",
        f"{DIM}src>{d.src_thr}{RESET}",
        f"{DIM}new/s>{human_num(d.newconn_thr)}{RESET}",
    ]
    github_seg = f"{ACCENT}{GITHUB}{RESET}"
    hint_seg = f"{CYAN_B}Ctrl-C to quit{RESET}"
    segs = list(thr_segs) + [github_seg, hint_seg]
    footer = f"thr: {' '.join(segs)}"
    while len(_visible(footer)) > width - 2 and len(segs) > 1:
        if segs[-1] == hint_seg:
            segs.pop()
        elif len(segs) > 2:
            segs.pop(-2)
        else:
            break
        footer = f"thr: {' '.join(segs)}"
    lines.append(_row(footer, width))
    lines.append(_bot_line(width))

    body = "\n".join(lines)
    if sys.stdout.isatty():
        sys.stdout.write(HOME + body + "\n" + ERASE_DOWN)
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
    dashboard = sys.stdout.isatty() and not args.no_dashboard
    if dashboard:
        sys.stdout.write(ALT_ENTER + HIDE_CURSOR)
        sys.stdout.flush()
    try:
        log.info("DDoS detector started (interval=%ss)", args.interval)
        if not dashboard:
            d.render = lambda self, cur, findings: None
        d.run()
    except KeyboardInterrupt:
        if dashboard:
            sys.stdout.write("\n" + RESET)
        log.info("stopped")
    finally:
        if dashboard:
            sys.stdout.write(SHOW_CURSOR + ALT_EXIT)
            sys.stdout.flush()
        if out:
            out.close()


if __name__ == "__main__":
    main()
