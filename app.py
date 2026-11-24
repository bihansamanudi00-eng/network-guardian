import os
import sys
import queue
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

from guardian import NetworkGuardian, list_capture_interfaces

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Guardian | Network Security Monitor")
        self.root.geometry("1180x780")
        self.root.minsize(980, 650)
        self.root.configure(bg="#0b1220")
        self.events = queue.Queue()
        self.guardian = NetworkGuardian(self.events)
        self.interfaces = []
        self._style()
        self._build()
        self.refresh_saved()
        self.root.after(250, self.poll_events)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TCombobox", fieldbackground="#172338", background="#172338",
                        foreground="#e7eefc", arrowcolor="#e7eefc")
        style.configure("Treeview", background="#111c2e", foreground="#e7eefc",
                        fieldbackground="#111c2e", rowheight=26, borderwidth=0)
        style.configure("Treeview.Heading", background="#1c2b42", foreground="#dbeafe",
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1d4ed8")])

    def label(self, parent, text, size=10, color="#cbd5e1", bold=False):
        return tk.Label(parent, text=text, bg=parent["bg"], fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"))

    def _build(self):
        header = tk.Frame(self.root, bg="#101b2d", padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="🛡  NETWORK GUARDIAN", bg="#101b2d", fg="#f8fafc",
                 font=("Segoe UI", 20, "bold")).pack(side="left")
        tk.Label(header, text="Live network monitoring • Rule-based detection • ML anomaly detection",
                 bg="#101b2d", fg="#94a3b8", font=("Segoe UI", 9)).pack(side="left", padx=18, pady=(8,0))

        controls = tk.Frame(self.root, bg="#0b1220", padx=20, pady=14)
        controls.pack(fill="x")
        self.label(controls, "CAPTURE INTERFACE", 9, "#93c5fd", True).pack(side="left")
        self.iface_var = tk.StringVar()
        self.combo = ttk.Combobox(controls, textvariable=self.iface_var, width=65, state="readonly")
        self.combo.pack(side="left", padx=10)
        ttk.Button(controls, text="Find interfaces", command=self.find_interfaces).pack(side="left", padx=4)
        self.start_btn = ttk.Button(controls, text="▶  Start monitoring", command=self.start)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(controls, text="■  Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Button(controls, text="Train AI model", command=self.train).pack(side="left", padx=4)

        cards = tk.Frame(self.root, bg="#0b1220", padx=16)
        cards.pack(fill="x")
        self.packet_value = self.card(cards, "PACKETS CAPTURED", "0", "#38bdf8")
        self.tcp_value = self.card(cards, "TCP PACKETS", "0", "#60a5fa")
        self.udp_value = self.card(cards, "UDP PACKETS", "0", "#34d399")
        self.icmp_value = self.card(cards, "ICMP PACKETS", "0", "#c084fc")
        self.alert_value = self.card(cards, "ALERTS THIS SESSION", "0", "#fb7185")

        status_frame = tk.Frame(self.root, bg="#101b2d", padx=18, pady=9)
        status_frame.pack(fill="x", padx=20, pady=12)
        self.status_var = tk.StringVar(value="Ready – choose your Wi-Fi interface and start monitoring")
        tk.Label(status_frame, textvariable=self.status_var, bg="#101b2d", fg="#cbd5e1",
                 font=("Segoe UI", 9)).pack(side="left")
        self.model_var = tk.StringVar(value=self.guardian.model_status)
        tk.Label(status_frame, textvariable=self.model_var, bg="#101b2d", fg="#a5b4fc",
                 font=("Segoe UI", 9)).pack(side="right")

        body = tk.Frame(self.root, bg="#0b1220", padx=20)
        body.pack(fill="both", expand=True)
        left = tk.Frame(body, bg="#0b1220")
        left.pack(side="left", fill="both", expand=True, padx=(0,8))
        right = tk.Frame(body, bg="#0b1220")
        right.pack(side="left", fill="both", expand=True, padx=(8,0))

        self.section(left, "LIVE TRAFFIC WINDOWS")
        self.traffic = self.make_table(left, ("time","source","packets","tcp","udp","icmp","ports","dns"),
                                       ("Time","Source IP","Packets","TCP","UDP","ICMP","Ports","DNS"),
                                       [130,135,65,55,55,55,55,55])
        self.section(right, "RECENT SECURITY ALERTS")
        self.alerts = self.make_table(right, ("time","severity","type","source","details"),
                                      ("Time","Level","Alert type","Source IP","Details"),
                                      [130,65,130,115,260])
        foot = tk.Frame(self.root, bg="#101b2d", padx=18, pady=10)
        foot.pack(fill="x", padx=20, pady=12)
        tk.Label(foot, text="Authorized monitoring only. Alerts are investigation indicators, not proof of compromise.",
                 bg="#101b2d", fg="#94a3b8", font=("Segoe UI", 8)).pack(side="left")
        ttk.Button(foot, text="Refresh history", command=self.refresh_saved).pack(side="right")

    def card(self, parent, title, value, accent):
        frame = tk.Frame(parent, bg="#142238", padx=14, pady=12, highlightbackground="#263852", highlightthickness=1)
        frame.pack(side="left", fill="x", expand=True, padx=4, pady=4)
        tk.Label(frame, text=title, bg="#142238", fg="#94a3b8", font=("Segoe UI", 8, "bold")).pack(anchor="w")
        val = tk.Label(frame, text=value, bg="#142238", fg=accent, font=("Segoe UI", 22, "bold"))
        val.pack(anchor="w", pady=(3,0))
        return val

    def section(self, parent, title):
        tk.Label(parent, text=title, bg="#0b1220", fg="#e2e8f0",
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(2,8))

    def make_table(self, parent, keys, headings, widths):
        frame = tk.Frame(parent, bg="#0b1220")
        frame.pack(fill="both", expand=True)
        table = ttk.Treeview(frame, columns=keys, show="headings", height=16)
        for key, heading, width in zip(keys, headings, widths):
            table.heading(key, text=heading)
            table.column(key, width=width, minwidth=45, stretch=True)
        y = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=y.set)
        table.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")
        return table

    def find_interfaces(self):
        try:
            self.interfaces = list_capture_interfaces()
            values = [f"{name}  |  {desc}" for name, desc in self.interfaces]
            self.combo["values"] = values
            # Prefer the actual Intel Wi-Fi adapter if it is present.
            preferred = next((i for i, x in enumerate(values) if "Wi-Fi 6E AX211" in x or "Wi-Fi" in x and "Direct" not in x), 0)
            if values:
                self.combo.current(preferred)
                self.status_var.set(f"Found {len(values)} capture interfaces. Select the active Wi-Fi adapter.")
            else:
                self.status_var.set("No capture interfaces found. Check Npcap installation.")
        except Exception as e:
            messagebox.showerror("Interface discovery failed", str(e))

    def selected_iface(self):
        idx = self.combo.current()
        if idx < 0 or idx >= len(self.interfaces):
            return None
        return self.interfaces[idx][0]

    def start(self):
        iface = self.selected_iface()
        if not iface:
            messagebox.showwarning("Choose interface", "Click Find interfaces and select your active Wi-Fi adapter.")
            return
        # Start fresh session counters; saved history remains in SQLite.
        self._counts = {"tcp_count": 0, "udp_count": 0, "icmp_count": 0, "alerts": 0}
        self.tcp_value.configure(text="0")
        self.udp_value.configure(text="0")
        self.icmp_value.configure(text="0")
        self.alert_value.configure(text="0")
        self.packet_value.configure(text="0")
        self.guardian.start(iface)
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

    def stop(self):
        self.guardian.stop()
        self.stop_btn.configure(state="disabled")
        self.start_btn.configure(state="normal")

    def train(self):
        try:
            result = self.guardian.train_model()
            self.model_var.set(result)
            messagebox.showinfo("AI model trained", result + "\n\nThe model will be used for anomaly detection during the next monitoring session.")
        except Exception as e:
            messagebox.showwarning("Training not available yet", str(e))

    def poll_events(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "packet":
                    self.packet_value.configure(text=str(data))
                elif kind == "traffic":
                    self._counter("tcp_count")
                    self._counts["tcp_count"] += int(data.get("tcp_count", 0))
                    self._counts["udp_count"] += int(data.get("udp_count", 0))
                    self._counts["icmp_count"] += int(data.get("icmp_count", 0))
                    self.tcp_value.configure(text=str(self._counts["tcp_count"]))
                    self.udp_value.configure(text=str(self._counts["udp_count"]))
                    self.icmp_value.configure(text=str(self._counts["icmp_count"]))
                    self.traffic.insert("", 0, values=(
                        data["timestamp"].split(" ")[1], data["source_ip"], data["packet_count"],
                        data["tcp_count"], data["udp_count"], data["icmp_count"],
                        data["unique_destination_ports"], data["dns_query_count"]))
                    self.trim(self.traffic, 150)
                elif kind == "alert":
                    self._counter("alerts")
                    self._counts["alerts"] += 1
                    self.alert_value.configure(text=str(self._counts["alerts"]))
                    self.alerts.insert("", 0, values=(
                        data["timestamp"].split(" ")[1], data["severity"], data["alert_type"],
                        data["source_ip"], data["details"]))
                    self.trim(self.alerts, 150)
                elif kind == "status":
                    self.status_var.set(data)
                elif kind == "error":
                    self.status_var.set("Capture error")
                    messagebox.showerror("Network capture error", data)
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(250, self.poll_events)

    def _counter(self, key):
        if not hasattr(self, "_counts"):
            self._counts = {"tcp_count":0,"udp_count":0,"icmp_count":0,"alerts":0}
        return self._counts[key]

    def trim(self, table, maximum):
        children = table.get_children()
        for item in children[maximum:]:
            table.delete(item)

    def refresh_saved(self):
        try:
            for item in self.traffic.get_children():
                self.traffic.delete(item)
            for item in self.alerts.get_children():
                self.alerts.delete(item)
            for r in self.guardian.recent_traffic():
                self.traffic.insert("", "end", values=(r[0].split(" ")[1],r[1],r[2],r[3],r[4],r[5],r[6],r[7]))
            for r in self.guardian.recent_alerts():
                self.alerts.insert("", "end", values=(r[0].split(" ")[1],r[1],r[2],r[3],r[4]))
        except Exception as e:
            self.status_var.set(f"Could not refresh history: {e}")

    def close(self):
        self.guardian.stop()
        try:
            if self.guardian.thread and self.guardian.thread.is_alive():
                self.guardian.thread.join(timeout=2)
        except Exception:
            pass
        self.guardian.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    app.find_interfaces()
    root.mainloop()
