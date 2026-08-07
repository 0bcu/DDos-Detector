#!/usr/bin/env python3
"""
DDos Detector - graphical interface.

White/black minimal dashboard built with Tkinter. Reuses the /proc sampling
and detection logic from detector.py; runs the sampler on a background
thread and refreshes the UI through a queue.

Usage:
    python3 gui.py
    python3 gui.py -i eth0

Linux only. Tkinter ships with the standard Python install.
"""

import argparse
import json
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk

import detector as core

BG = "#ffffff"
FG = "#111111"
DIM = "#666666"
BORDER = "#dddddd"
NORMAL = "#1b8a3a"
ATTACK = "#c62828"
ACCENT = "#222222"
ROW = "#f7f7f7"


def fmt_bytes(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024


def fmt_num(n):
    for u in ("", "K", "M"):
        if n < 1000 or u == "M":
            return f"{n:.0f}" if u == "" else f"{n:.1f}{u}"
        n /= 1000


class Dashboard(tk.Tk):
    def __init__(self, det):
        super().__init__()
        self.det = det
        self.alerts = queue.Queue()
        self.status_label = None
        self.worker = None
        self.running = False
        self.setup_window()
        self.build_ui()

    # ---------------------------------------------------------------- window
    def setup_window(self):
        self.title("DDoS Detector")
        self.configure(bg=BG)
        self.geometry("980x680")
        self.minsize(860, 600)
        self.option_add("*Font", ("Segoe UI", 10))

    # -------------------------------------------------------------------- ui
    def build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=BG,
                        bordercolor=BORDER, relief="solid", borderwidth=1)
        style.configure("TLabelframe", background=BG, bordercolor=BORDER,
                        relief="solid")
        style.configure("TLabelframe.Label", background=BG, foreground=FG,
                        font=("Segoe UI", 10, "bold"))
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("DIM.TLabel", background=BG, foreground=DIM)
        style.configure("Treeview", background=BG, fieldbackground=BG,
                        foreground=FG, bordercolor=BORDER,
                        font=("Consolas", 10))
        style.configure("Treeview.Heading", background=BG, foreground=FG,
                        bordercolor=BORDER, font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)])
        style.configure("TButton", background=BG, foreground=FG,
                        bordercolor=BORDER, focuscolor=BG)
        style.map("TButton", background=[("active", "#eeeeee")])
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"))

        root = ttk.Frame(self, style="TFrame", padding=14)
        root.pack(fill="both", expand=True)

        self.status_label = tk.Label(root, text="NORMAL", bg=NORMAL, fg="#ffffff",
                                     font=("Segoe UI", 16, "bold"), anchor="center")
        self.status_label.pack(fill="x", pady=(0, 10))

        summary = ttk.Frame(root, style="TFrame")
        summary.pack(fill="x", pady=(0, 10))
        self.summary_vars = {}
        for key, label in (("connections", "connections"),
                           ("new_conn", "new conn/s"),
                           ("src_tcp", "src IP (tcp)"),
                           ("src_udp", "src IP (udp)"),
                           ("total_src", "src IP (total)")):
            card = ttk.Frame(summary, style="Card.TFrame", padding=(10, 6))
            card.pack(side="left", fill="x", expand=True, padx=(0, 8))
            ttk.Label(card, text=label, style="DIM.TLabel").pack(anchor="w")
            var = tk.StringVar(value="0")
            ttk.Label(card, textvariable=var,
                      font=("Consolas", 14, "bold")).pack(anchor="w")
            self.summary_vars[key] = var

        mid = ttk.Frame(root, style="TFrame")
        mid.pack(fill="both", expand=True, pady=(0, 10))

        self.iface_tree = self.make_table(
            mid, ("interface", "rx pkt/s", "tx pkt/s", "rx/s", "tx/s", "drop/s"),
            left=True)
        self.iface_tree["show"] = "headings"

        tcp_card = ttk.Frame(mid, style="Card.TFrame", padding=(10, 6))
        tcp_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
        ttk.Label(tcp_card, text="TCP states",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        self.state_tree = self.make_table(tcp_card, ("state", "count", "note"))
        self.state_tree["show"] = "headings"

        alerts_frame = ttk.LabelFrame(root, text="alerts", padding=8)
        alerts_frame.pack(fill="x", pady=(0, 10))
        self.alert_box = tk.Text(alerts_frame, height=5, bg=BG, fg=FG,
                                 relief="flat", wrap="none", state="disabled",
                                 font=("Consolas", 10))
        self.alert_box.pack(fill="x")
        self.alert_box.tag_configure("warn", foreground=ATTACK)

        controls = ttk.Frame(root, style="TFrame")
        controls.pack(fill="x")
        self.thr_vars = {}
        thresholds = (("pkt/s", "pkt_thr", 20000), ("bytes/s", "byte_thr", 50000000),
                      ("SYN_RECV", "syn_thr", 500), ("conn", "conn_thr", 30000),
                      ("src IP", "src_thr", 1000), ("new/s", "newconn_thr", 2000))
        for label, key, default in thresholds:
            box = ttk.Frame(controls, style="TFrame")
            box.pack(side="left", padx=(0, 10))
            ttk.Label(box, text=label, style="DIM.TLabel").pack(anchor="w")
            var = tk.StringVar(value=str(default))
            ttk.Entry(box, textvariable=var, width=9, justify="right",
                      font=("Consolas", 10)).pack()
            self.thr_vars[key] = var
        ttk.Label(controls, text="interval (s)", style="DIM.TLabel").pack(
            side="left", anchor="s", padx=(0, 4))
        self.interval_var = tk.StringVar(value="1")
        ttk.Entry(controls, textvariable=self.interval_var, width=5,
                  justify="right", font=("Consolas", 10)).pack(
            side="left", anchor="s", padx=(0, 14))

        self.run_btn = ttk.Button(controls, text="START", style="Accent.TButton",
                                  command=self.toggle)
        self.run_btn.pack(side="right")

    def make_table(self, parent, columns, left=False):
        tree = ttk.Treeview(parent, columns=columns, height=8,
                            show="tree headings" if not left else "headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=120, anchor="w" if left else "center")
        if not left:
            tree.column("#0", width=0, stretch=False)
        tree.pack(side="left" if left else "top", fill="both", expand=True)
        return tree

    # ------------------------------------------------------------- sampling
    def toggle(self):
        if self.running:
            self.stop()
        else:
            self.start()

    def start(self):
        try:
            for key, var in self.thr_vars.items():
                setattr(self.det, key, max(1, int(var.get())))
            self.det.interval = max(0.2, float(self.interval_var.get()))
        except ValueError:
            self.push_alert("bad threshold value - ignored", warn=True)
        self.det.prev = self.det.snapshot()
        self.running = True
        self.run_btn.configure(text="STOP")
        self.worker = threading.Thread(target=self.sample, daemon=True)
        self.worker.start()

    def stop(self):
        self.running = False
        self.run_btn.configure(text="START")
        self.set_status(False)

    def sample(self):
        while self.running:
            cur = self.det.snapshot()
            findings = self.det.analyze(cur)
            self.alerts.put((cur, findings))
            time.sleep(self.det.interval)

    def poll(self):
        try:
            while True:
                cur, findings = self.alerts.get_nowait()
                self.refresh(cur, findings)
        except queue.Empty:
            pass
        self.after(250, self.poll)

    def refresh(self, cur, findings):
        under = bool(findings)
        self.set_status(under)
        for kind, info in findings.items():
            self.push_alert(f"{time.strftime('%H:%M:%S')}  {kind.upper()}  "
                            f"{json.dumps(info, default=str)}", warn=True)

        self.iface_tree.delete(*self.iface_tree.get_children())
        for iface, c in cur["dev"].items():
            if self.det.iface and iface != self.det.iface:
                continue
            p = self.det.prev["dev"].get(iface) if self.det.prev else None
            rx_p = tx_p = rx_b = tx_b = drop = 0.0
            if p:
                rx_p = core.Detector._rate(cur["ts"], self.det.prev["ts"],
                                           p["rx_packets"], c["rx_packets"])
                tx_p = core.Detector._rate(cur["ts"], self.det.prev["ts"],
                                           p["tx_packets"], c["tx_packets"])
                rx_b = core.Detector._rate(cur["ts"], self.det.prev["ts"],
                                           p["rx_bytes"], c["rx_bytes"])
                tx_b = core.Detector._rate(cur["ts"], self.det.prev["ts"],
                                           p["tx_bytes"], c["tx_bytes"])
                drop = core.Detector._rate(cur["ts"], self.det.prev["ts"],
                                           p["rx_drop"], c["rx_drop"])
            hit = rx_p + tx_p > self.det.pkt_thr or rx_b + tx_b > self.det.byte_thr
            tag = "hit" if hit else ""
            self.iface_tree.insert("", "end",
                                   values=(iface, fmt_num(rx_p), fmt_num(tx_p),
                                           fmt_bytes(rx_b), fmt_bytes(tx_b),
                                           fmt_num(drop)), tags=(tag,))
        self.iface_tree.tag_configure("hit", foreground=ATTACK)

        self.state_tree.delete(*self.state_tree.get_children())
        states = cur["states"]
        for state in core.LOG_STATES + ("LISTEN",):
            count = states.get(state, 0)
            note = ""
            if state == "SYN_RECV" and count > self.det.syn_thr:
                note = "SYN flood"
            self.state_tree.insert("", "end", values=(state, fmt_num(count), note))

        self.summary_vars["connections"].set(fmt_num(cur["connections"]))
        new_conn = ((cur["connections"] - self.det.prev["connections"])
                    / self.det.interval)
        self.summary_vars["new_conn"].set(fmt_num(new_conn))
        self.summary_vars["src_tcp"].set(cur["tcp_src"])
        self.summary_vars["src_udp"].set(cur["udp_src"])
        self.summary_vars["total_src"].set(cur["src_total"])

    def set_status(self, under):
        self.status_label.configure(text="UNDER ATTACK" if under else "NORMAL",
                                    bg=ATTACK if under else NORMAL)

    def push_alert(self, text, warn=False):
        self.alert_box.configure(state="normal")
        self.alert_box.insert("end", text + "\n", "warn" if warn else ())
        self.alert_box.see("end")
        self.alert_box.configure(state="disabled")


def main():
    parser = argparse.ArgumentParser(description="DDoS Detector - GUI")
    parser.add_argument("-i", "--iface", help="monitor only this interface")
    args = parser.parse_args()
    app = Dashboard(core.Detector(iface=args.iface))
    app.after(250, app.poll)
    app.mainloop()


if __name__ == "__main__":
    main()
