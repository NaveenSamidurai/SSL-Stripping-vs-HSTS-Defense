"""
SSL Stripping (MITM) vs HSTS Defense - Cyber Range Simulation
Topic: SSL Stripping Attack vs HSTS Defense Mechanism
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import random
import hashlib
import base64
import json
import datetime
from collections import defaultdict


# ─────────────────────────────────────────────────────────────
#  Simulation Data & Logic
# ─────────────────────────────────────────────────────────────

SITES = [
    {"name": "bank.example.com",    "hsts": True,  "hsts_max_age": 31536000, "sensitive": True},
    {"name": "shop.example.com",    "hsts": True,  "hsts_max_age": 86400,    "sensitive": True},
    {"name": "news.example.com",    "hsts": False, "hsts_max_age": 0,        "sensitive": False},
    {"name": "login.example.com",   "hsts": True,  "hsts_max_age": 63072000, "sensitive": True},
    {"name": "oldsite.example.com", "hsts": False, "hsts_max_age": 0,        "sensitive": False},
]

SAMPLE_HEADERS = {
    "bank.example.com": {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Type": "text/html; charset=UTF-8",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    },
    "news.example.com": {
        "Content-Type": "text/html; charset=UTF-8",
        "Server": "Apache/2.4.41",
    },
}

FAKE_CREDS = [
    ("alice@bank.com",    "p@ssw0rd123"),
    ("bob@shop.com",      "secret_bob"),
    ("charlie@news.com",  "news_pass"),
]

EVENT_LOG = []
HSTS_CACHE = {}   # domain -> expiry timestamp
ATTACK_STATS = {"attempts": 0, "success": 0, "blocked": 0, "intercepted_creds": []}


def reset_stats():
    global HSTS_CACHE, ATTACK_STATS, EVENT_LOG
    EVENT_LOG.clear()
    HSTS_CACHE.clear()
    ATTACK_STATS = {"attempts": 0, "success": 0, "blocked": 0, "intercepted_creds": []}


def simulate_hsts_preload(domain):
    """Populate HSTS cache as if browser has visited before (preload)."""
    for site in SITES:
        if site["name"] == domain and site["hsts"]:
            HSTS_CACHE[domain] = time.time() + site["hsts_max_age"]
            return True
    return False


def is_hsts_cached(domain):
    if domain in HSTS_CACHE:
        if HSTS_CACHE[domain] > time.time():
            return True
        else:
            del HSTS_CACHE[domain]
    return False


def attempt_ssl_strip(domain, hsts_defense_enabled, preloaded):
    """
    Simulate one SSL stripping attempt.
    Returns: (success, reason, intercepted_credential)
    """
    ATTACK_STATS["attempts"] += 1
    site = next((s for s in SITES if s["name"] == domain), None)
    if not site:
        return False, "Domain not found", None

    # 1. HSTS preload cache check (strongest defense)
    if preloaded and is_hsts_cached(domain):
        ATTACK_STATS["blocked"] += 1
        return False, "BLOCKED — HSTS preload cache: browser enforces HTTPS directly", None

    # 2. HSTS header defense (only effective if site sends it & not first visit)
    if hsts_defense_enabled and site["hsts"]:
        # First visit is vulnerable; subsequent visits are protected
        if domain in HSTS_CACHE:
            ATTACK_STATS["blocked"] += 1
            return False, "BLOCKED — HSTS header remembered: browser refuses HTTP downgrade", None
        else:
            # First visit: HSTS header received AFTER connection, strip can happen
            intercept = random.choice(FAKE_CREDS) if site["sensitive"] else None
            if intercept:
                ATTACK_STATS["intercepted_creds"].append(intercept)
                ATTACK_STATS["success"] += 1
                # Store HSTS for next time
                HSTS_CACHE[domain] = time.time() + site["hsts_max_age"]
                return True, "⚠ FIRST-VISIT VULNERABLE — credentials intercepted before HSTS kicks in", intercept
            ATTACK_STATS["success"] += 1
            HSTS_CACHE[domain] = time.time() + site["hsts_max_age"]
            return True, "⚠ FIRST-VISIT VULNERABLE — traffic downgraded to HTTP (no credentials this time)", None

    # 3. No HSTS — fully vulnerable
    intercept = random.choice(FAKE_CREDS) if site["sensitive"] else None
    if intercept:
        ATTACK_STATS["intercepted_creds"].append(intercept)
    ATTACK_STATS["success"] += 1
    return True, "✗ ATTACK SUCCEEDED — no HSTS, full HTTP downgrade", intercept


def fake_http_request(domain, https=False):
    proto = "https" if https else "http"
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    return f"[{ts}]  GET {proto}://{domain}/  HTTP/1.1\n  Host: {domain}\n  User-Agent: Mozilla/5.0\n"


def fake_response_headers(domain, stripped=False):
    headers = SAMPLE_HEADERS.get(domain, {"Content-Type": "text/html"})
    lines = []
    proto = "HTTP/1.1 200 OK" if not stripped else "HTTP/1.1 200 OK  [STRIPPED]"
    lines.append(proto)
    for k, v in headers.items():
        if stripped and k == "Strict-Transport-Security":
            lines.append(f"  [REMOVED] {k}: {v}")
        else:
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
#  Colour Palette
# ─────────────────────────────────────────────────────────────
C = {
    "bg":       "#0d1117",
    "panel":    "#161b22",
    "border":   "#30363d",
    "accent":   "#58a6ff",
    "green":    "#3fb950",
    "red":      "#f85149",
    "yellow":   "#d29922",
    "purple":   "#bc8cff",
    "text":     "#e6edf3",
    "muted":    "#8b949e",
    "success_bg":"#0f2a1b",
    "danger_bg": "#2a0f0f",
    "warn_bg":   "#2a1f0a",
    "btn_blue":  "#1f6feb",
    "btn_red":   "#b91c1c",
    "btn_green": "#1a7f37",
}


# ─────────────────────────────────────────────────────────────
#  Main Application
# ─────────────────────────────────────────────────────────────
class SSLStripSimApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 SSL Stripping (MITM) vs HSTS Defense — Cyber Range")
        self.geometry("1280x820")
        self.minsize(1100, 700)
        self.configure(bg=C["bg"])
        self.resizable(True, True)

        self._setup_styles()
        self._build_ui()
        self._update_stats_display()

    # ── Styles ──────────────────────────────────────────────
    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TFrame",        background=C["bg"])
        style.configure("Panel.TFrame",  background=C["panel"])
        style.configure("TLabel",        background=C["bg"],    foreground=C["text"], font=("Consolas", 10))
        style.configure("Title.TLabel",  background=C["bg"],    foreground=C["accent"], font=("Consolas", 13, "bold"))
        style.configure("Head.TLabel",   background=C["panel"], foreground=C["accent"], font=("Consolas", 11, "bold"))
        style.configure("Muted.TLabel",  background=C["panel"], foreground=C["muted"],  font=("Consolas", 9))
        style.configure("Panel.TLabel",  background=C["panel"], foreground=C["text"],   font=("Consolas", 10))
        style.configure("Stat.TLabel",   background=C["panel"], foreground=C["text"],   font=("Consolas", 18, "bold"))
        style.configure("StatSub.TLabel",background=C["panel"], foreground=C["muted"],  font=("Consolas", 8))
        style.configure("TCheckbutton",  background=C["panel"], foreground=C["text"],   font=("Consolas", 10),
                        selectcolor=C["btn_blue"], indicatorcolor=C["border"])
        style.map("TCheckbutton", background=[("active", C["panel"])])
        style.configure("TCombobox",     font=("Consolas", 10), fieldbackground=C["border"],
                        background=C["border"], foreground=C["text"], selectbackground=C["btn_blue"])
        style.configure("TNotebook",     background=C["bg"],    tabmargins=[2, 5, 0, 0])
        style.configure("TNotebook.Tab", background=C["panel"], foreground=C["muted"],
                        font=("Consolas", 10), padding=[10, 4])
        style.map("TNotebook.Tab",
                  background=[("selected", C["bg"])],
                  foreground=[("selected", C["accent"])])
        style.configure("TSeparator", background=C["border"])

    # ── Layout ──────────────────────────────────────────────
    def _build_ui(self):
        # ── Header
        hdr = tk.Frame(self, bg=C["panel"], height=52)
        hdr.pack(fill="x", padx=0, pady=0)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  🛡  SSL Stripping (MITM) vs HSTS Defense  —  Cyber Range Simulation",
                 bg=C["panel"], fg=C["accent"], font=("Consolas", 14, "bold")).pack(side="left", padx=16, pady=12)
        tk.Label(hdr, text="Attack-Defense Simulation  |  Network Security Lab",
                 bg=C["panel"], fg=C["muted"], font=("Consolas", 9)).pack(side="right", padx=20)

        sep = tk.Frame(self, bg=C["border"], height=1)
        sep.pack(fill="x")

        # ── Main body
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=10, pady=8)

        # Left control panel
        left = tk.Frame(body, bg=C["panel"], width=320)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)
        self._build_left(left)

        # Right notebook
        right = tk.Frame(body, bg=C["bg"])
        right.pack(side="left", fill="both", expand=True)
        self._build_right(right)

    def _build_left(self, parent):
        pad = {"padx": 14, "pady": 4}

        tk.Label(parent, text="ATTACK CONFIGURATION", bg=C["panel"],
                 fg=C["accent"], font=("Consolas", 10, "bold")).pack(anchor="w", padx=14, pady=(14, 4))
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=14, pady=2)

        # Target domain
        tk.Label(parent, text="Target Domain:", bg=C["panel"], fg=C["muted"],
                 font=("Consolas", 9)).pack(anchor="w", **pad)
        self.domain_var = tk.StringVar(value=SITES[0]["name"])
        domain_cb = ttk.Combobox(parent, textvariable=self.domain_var,
                                  values=[s["name"] for s in SITES], state="readonly", width=28)
        domain_cb.pack(anchor="w", padx=14, pady=2)
        domain_cb.bind("<<ComboboxSelected>>", lambda e: self._update_site_info())

        # Site info card
        self.site_info_frame = tk.Frame(parent, bg=C["bg"], bd=0)
        self.site_info_frame.pack(fill="x", padx=14, pady=6)
        self.site_hsts_lbl    = tk.Label(self.site_info_frame, text="", bg=C["bg"], fg=C["text"],
                                          font=("Consolas", 9), justify="left")
        self.site_hsts_lbl.pack(anchor="w", padx=8, pady=2)

        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=14, pady=4)

        # Defense toggles
        tk.Label(parent, text="DEFENSE SETTINGS", bg=C["panel"],
                 fg=C["accent"], font=("Consolas", 10, "bold")).pack(anchor="w", padx=14, pady=(6, 2))

        self.hsts_var    = tk.BooleanVar(value=True)
        self.preload_var = tk.BooleanVar(value=False)

        hsts_cb = tk.Checkbutton(parent, text=" Enable HSTS Defense",
                                  variable=self.hsts_var, bg=C["panel"], fg=C["text"],
                                  selectcolor=C["btn_blue"], activebackground=C["panel"],
                                  font=("Consolas", 10), command=self._on_defense_change)
        hsts_cb.pack(anchor="w", padx=14, pady=2)

        preload_cb = tk.Checkbutton(parent, text=" Preload HSTS Cache (simulate prior visit)",
                                     variable=self.preload_var, bg=C["panel"], fg=C["text"],
                                     selectcolor=C["btn_blue"], activebackground=C["panel"],
                                     font=("Consolas", 9), command=self._on_defense_change,
                                     wraplength=250, justify="left")
        preload_cb.pack(anchor="w", padx=14, pady=2)

        # Speed slider
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=14, pady=4)
        tk.Label(parent, text="Simulation Speed:", bg=C["panel"], fg=C["muted"],
                 font=("Consolas", 9)).pack(anchor="w", **pad)
        self.speed_var = tk.DoubleVar(value=0.6)
        speed_sl = tk.Scale(parent, from_=0.1, to=2.0, resolution=0.1, orient="horizontal",
                             variable=self.speed_var, bg=C["panel"], fg=C["text"],
                             troughcolor=C["border"], highlightthickness=0,
                             activebackground=C["btn_blue"], length=200, font=("Consolas", 8))
        speed_sl.pack(anchor="w", padx=14)
        tk.Label(parent, text="← faster          slower →",
                 bg=C["panel"], fg=C["muted"], font=("Consolas", 8)).pack(anchor="w", padx=14)

        # Burst count
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=14, pady=4)
        tk.Label(parent, text="Burst Attack Count:", bg=C["panel"], fg=C["muted"],
                 font=("Consolas", 9)).pack(anchor="w", **pad)
        self.burst_var = tk.IntVar(value=5)
        burst_sl = tk.Scale(parent, from_=1, to=20, orient="horizontal",
                             variable=self.burst_var, bg=C["panel"], fg=C["text"],
                             troughcolor=C["border"], highlightthickness=0,
                             activebackground=C["btn_blue"], length=200, font=("Consolas", 8))
        burst_sl.pack(anchor="w", padx=14)

        # Action buttons
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=14, pady=8)

        btn_style = {"font": ("Consolas", 10, "bold"), "bd": 0, "relief": "flat",
                     "cursor": "hand2", "pady": 7, "padx": 10}

        self.attack_btn = tk.Button(parent, text="▶  LAUNCH ATTACK",
                                     bg=C["btn_red"], fg="white",
                                     command=self._launch_single_attack, **btn_style)
        self.attack_btn.pack(fill="x", padx=14, pady=3)

        self.burst_btn = tk.Button(parent, text="⚡  BURST ATTACK",
                                    bg="#7d2222", fg="white",
                                    command=self._launch_burst_attack, **btn_style)
        self.burst_btn.pack(fill="x", padx=14, pady=3)

        self.preload_btn = tk.Button(parent, text="🔒  PRELOAD HSTS CACHE",
                                      bg=C["btn_green"], fg="white",
                                      command=self._do_preload, **btn_style)
        self.preload_btn.pack(fill="x", padx=14, pady=3)

        tk.Button(parent, text="🔄  RESET SIMULATION",
                  bg=C["border"], fg=C["text"],
                  command=self._reset_all, **btn_style).pack(fill="x", padx=14, pady=3)

        # HSTS Cache display
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=14, pady=6)
        tk.Label(parent, text="HSTS CACHE (Browser Memory):", bg=C["panel"],
                 fg=C["accent"], font=("Consolas", 9, "bold")).pack(anchor="w", padx=14)
        self.hsts_cache_text = tk.Text(parent, bg=C["bg"], fg=C["green"],
                                        font=("Consolas", 8), height=6, bd=0,
                                        insertbackground=C["text"], state="disabled")
        self.hsts_cache_text.pack(fill="x", padx=14, pady=4)

        self._update_site_info()

    def _build_right(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)

        # Tab 1: Live simulation
        sim_tab = tk.Frame(nb, bg=C["bg"])
        nb.add(sim_tab, text="  📡 Live Simulation  ")
        self._build_sim_tab(sim_tab)

        # Tab 2: Packet Inspector
        pkt_tab = tk.Frame(nb, bg=C["bg"])
        nb.add(pkt_tab, text="  🔍 Packet Inspector  ")
        self._build_packet_tab(pkt_tab)

        # Tab 3: Statistics
        stats_tab = tk.Frame(nb, bg=C["bg"])
        nb.add(stats_tab, text="  📊 Statistics  ")
        self._build_stats_tab(stats_tab)

        # Tab 4: How It Works
        theory_tab = tk.Frame(nb, bg=C["bg"])
        nb.add(theory_tab, text="  📚 How It Works  ")
        self._build_theory_tab(theory_tab)

        self.nb = nb

    # ── Simulation Tab ──────────────────────────────────────
    def _build_sim_tab(self, parent):
        # Top bar: status indicator
        top = tk.Frame(parent, bg=C["panel"], height=36)
        top.pack(fill="x")
        top.pack_propagate(False)
        self.status_dot = tk.Label(top, text="●", bg=C["panel"], fg=C["green"],
                                    font=("Consolas", 14))
        self.status_dot.pack(side="left", padx=10, pady=8)
        self.status_lbl = tk.Label(top, text="Simulation Ready  —  Configure attack parameters and launch",
                                    bg=C["panel"], fg=C["muted"], font=("Consolas", 9))
        self.status_lbl.pack(side="left")

        # Network diagram area
        diag = tk.Frame(parent, bg=C["bg"], height=130)
        diag.pack(fill="x", padx=8, pady=6)
        diag.pack_propagate(False)
        self._build_network_diagram(diag)

        # Log area
        log_frame = tk.Frame(parent, bg=C["bg"])
        log_frame.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        tk.Label(log_frame, text="▼  ATTACK LOG", bg=C["bg"], fg=C["accent"],
                 font=("Consolas", 10, "bold")).pack(anchor="w")

        self.log_text = scrolledtext.ScrolledText(
            log_frame, bg=C["panel"], fg=C["text"],
            font=("Consolas", 10), bd=0, insertbackground=C["text"],
            selectbackground=C["btn_blue"], wrap="word", state="disabled"
        )
        self.log_text.pack(fill="both", expand=True)
        # Tags for colours
        self.log_text.tag_config("success", foreground=C["red"])
        self.log_text.tag_config("blocked", foreground=C["green"])
        self.log_text.tag_config("warn",    foreground=C["yellow"])
        self.log_text.tag_config("info",    foreground=C["accent"])
        self.log_text.tag_config("header",  foreground=C["purple"])
        self.log_text.tag_config("cred",    foreground="#ff9f43", background="#2a1700")
        self.log_text.tag_config("muted",   foreground=C["muted"])

    def _build_network_diagram(self, parent):
        canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0, height=130)
        canvas.pack(fill="both", expand=True)
        self.net_canvas = canvas
        self._draw_network_static()

    def _draw_network_static(self):
        c = self.net_canvas
        c.delete("all")
        w = c.winfo_width() or 900
        h = 130

        # Nodes
        nodes = [
            (w * 0.10, h // 2, "👤", "Client\nBrowser",     C["accent"]),
            (w * 0.37, h // 2, "☠", "MITM\nAttacker",       C["red"]),
            (w * 0.65, h // 2, "🌐", "Target\nServer",       C["green"]),
            (w * 0.88, h // 2, "🛡", "HSTS\nPolicy",         C["purple"]),
        ]
        for x, y, icon, label, col in nodes:
            c.create_oval(x-28, y-28, x+28, y+28, fill=C["panel"], outline=col, width=2)
            c.create_text(x, y-6, text=icon, fill=col, font=("", 14))
            c.create_text(x, y+18, text=label, fill=col, font=("Consolas", 8), justify="center")

        # Arrows
        arrow_cfg = {"arrow": tk.LAST, "width": 2}
        # Client -> MITM (HTTP — dashed red)
        c.create_line(w*0.10+30, h//2, w*0.37-30, h//2, fill=C["red"], dash=(6, 3), **arrow_cfg)
        c.create_text((w*0.10 + w*0.37)/2, h//2 - 14, text="HTTP (stripped)", fill=C["red"],
                       font=("Consolas", 8))
        # MITM -> Server (HTTPS — solid green)
        c.create_line(w*0.37+30, h//2, w*0.65-30, h//2, fill=C["green"], **arrow_cfg)
        c.create_text((w*0.37 + w*0.65)/2, h//2 - 14, text="HTTPS (kept)", fill=C["green"],
                       font=("Consolas", 8))
        # Server -> HSTS
        c.create_line(w*0.65+30, h//2, w*0.88-30, h//2, fill=C["purple"], dash=(4, 4), **arrow_cfg)
        c.create_text((w*0.65 + w*0.88)/2, h//2 + 18, text="HSTS header", fill=C["purple"],
                       font=("Consolas", 8))

        self.net_nodes = nodes
        self.net_canvas.bind("<Configure>", lambda e: self._draw_network_static())

    # ── Packet Inspector Tab ────────────────────────────────
    def _build_packet_tab(self, parent):
        tk.Label(parent, text="INTERCEPTED PACKET ANALYSIS", bg=C["bg"],
                 fg=C["accent"], font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=(8, 2))

        pane = tk.PanedWindow(parent, orient="horizontal", bg=C["bg"], sashwidth=6,
                               sashrelief="flat", bd=0)
        pane.pack(fill="both", expand=True, padx=8, pady=4)

        # Left: Request packets
        req_frame = tk.Frame(pane, bg=C["panel"])
        pane.add(req_frame, minsize=200)
        tk.Label(req_frame, text="  HTTP Request (Stripped)", bg=C["panel"],
                 fg=C["red"], font=("Consolas", 10, "bold")).pack(anchor="w", pady=4)
        self.req_text = scrolledtext.ScrolledText(
            req_frame, bg="#1a0a0a", fg="#f78166",
            font=("Consolas", 10), bd=0, state="disabled", wrap="word")
        self.req_text.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        # Right: Response packets
        resp_frame = tk.Frame(pane, bg=C["panel"])
        pane.add(resp_frame, minsize=200)
        tk.Label(resp_frame, text="  Server Response Headers", bg=C["panel"],
                 fg=C["green"], font=("Consolas", 10, "bold")).pack(anchor="w", pady=4)
        self.resp_text = scrolledtext.ScrolledText(
            resp_frame, bg="#0a1a0a", fg="#7ee787",
            font=("Consolas", 10), bd=0, state="disabled", wrap="word")
        self.resp_text.pack(fill="both", expand=True, padx=6, pady=(0, 6))

    # ── Stats Tab ───────────────────────────────────────────
    def _build_stats_tab(self, parent):
        tk.Label(parent, text="SIMULATION STATISTICS", bg=C["bg"],
                 fg=C["accent"], font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=(8, 4))

        # Stat cards row
        cards_row = tk.Frame(parent, bg=C["bg"])
        cards_row.pack(fill="x", padx=8, pady=4)

        self.stat_cards = {}
        for key, label, col in [
            ("attempts",    "Total Attempts",      C["accent"]),
            ("success",     "Attacks Succeeded",   C["red"]),
            ("blocked",     "Attacks Blocked",     C["green"]),
            ("intercepted", "Credentials Stolen",  C["yellow"]),
        ]:
            card = tk.Frame(cards_row, bg=C["panel"], padx=14, pady=10)
            card.pack(side="left", fill="both", expand=True, padx=4)
            val_lbl = tk.Label(card, text="0", bg=C["panel"], fg=col, font=("Consolas", 28, "bold"))
            val_lbl.pack()
            tk.Label(card, text=label, bg=C["panel"], fg=C["muted"], font=("Consolas", 9)).pack()
            self.stat_cards[key] = val_lbl

        # Bar chart (canvas)
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=10, pady=8)
        tk.Label(parent, text="ATTACK RESULT BREAKDOWN", bg=C["bg"],
                 fg=C["muted"], font=("Consolas", 9, "bold")).pack(anchor="w", padx=10)
        self.bar_canvas = tk.Canvas(parent, bg=C["panel"], height=160,
                                     highlightthickness=0)
        self.bar_canvas.pack(fill="x", padx=10, pady=4)
        self.bar_canvas.bind("<Configure>", lambda e: self._draw_bar_chart())

        # Intercepted credentials list
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=10, pady=4)
        tk.Label(parent, text="⚠  INTERCEPTED CREDENTIALS", bg=C["bg"],
                 fg=C["red"], font=("Consolas", 10, "bold")).pack(anchor="w", padx=10)
        self.cred_text = scrolledtext.ScrolledText(
            parent, bg=C["danger_bg"], fg="#ff9f43",
            font=("Consolas", 10), bd=0, state="disabled", height=6, wrap="word")
        self.cred_text.pack(fill="x", padx=10, pady=4)

    def _build_theory_tab(self, parent):
        text = scrolledtext.ScrolledText(
            parent, bg=C["panel"], fg=C["text"],
            font=("Consolas", 10), bd=0, wrap="word", state="disabled", padx=16, pady=12)
        text.pack(fill="both", expand=True, padx=8, pady=8)
        text.tag_config("h1",    foreground=C["accent"],  font=("Consolas", 13, "bold"))
        text.tag_config("h2",    foreground=C["purple"],  font=("Consolas", 11, "bold"))
        text.tag_config("code",  foreground=C["green"],   background=C["bg"], font=("Consolas", 10))
        text.tag_config("warn",  foreground=C["yellow"])
        text.tag_config("muted", foreground=C["muted"])

        text.config(state="normal")
        content = [
            ("h1", "SSL Stripping (MITM) Attack vs HSTS Defense\n\n"),
            ("h2", "What is SSL Stripping?\n"),
            ("", """SSL Stripping is a Man-in-the-Middle (MITM) attack first demonstrated by Moxie
Marlinspike in 2009. It downgrades a victim's HTTPS connection to HTTP without
their knowledge, allowing the attacker to read and modify plaintext traffic.\n\n"""),
            ("h2", "Attack Flow\n"),
            ("code", """  1. Victim connects to network (e.g., public Wi-Fi)
  2. Attacker performs ARP Poisoning → becomes MITM
  3. Victim types http://bank.com or clicks an HTTP link
  4. Attacker intercepts the HTTP request
  5. Attacker makes HTTPS request to server on victim's behalf
  6. Attacker strips the HTTPS from server responses → serves HTTP to victim
  7. Victim never sees HTTPS — connection looks normal (no padlock)\n\n"""),
            ("h2", "Why It Works\n"),
            ("", """HTTP → HTTPS redirect is vulnerable: the very first request goes over HTTP.
If a user types 'bank.com' (without https://), the browser first sends a plain
HTTP request. The attacker intercepts this before any redirect happens.\n\n"""),
            ("h2", "What is HSTS?\n"),
            ("", """HTTP Strict Transport Security (HSTS) is a security policy mechanism
(RFC 6797) that tells browsers to ONLY use HTTPS for a domain, refusing any
HTTP connections — even if the user types http://.\n\n"""),
            ("code", """  Response Header:
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n"""),
            ("h2", "How HSTS Defends\n"),
            ("warn", """  ✓ After first HTTPS visit: browser caches HSTS policy
  ✓ All future visits to that domain → forced to HTTPS internally
  ✓ Browser refuses the MITM's HTTP response
  ✓ SSL stripping fails — no HTTP connection is ever made\n\n"""),
            ("h2", "HSTS Limitations\n"),
            ("warn", """  ⚠ First-Visit Problem: HSTS doesn't protect the very first visit
  ⚠ New browser / cleared cache = vulnerable again
  ⚠ Preloaded HSTS list solves this (Chromium, Firefox built-in list)\n\n"""),
            ("h2", "HSTS Preload\n"),
            ("", """Browsers ship with a hardcoded list of HSTS domains (hstspreload.org).
These sites are ALWAYS contacted via HTTPS — even on first visit, even with
cleared cache. This is the strongest defense against SSL stripping.\n\n"""),
            ("muted", "  References: RFC 6797, OWASP SSL Stripping, Moxie Marlinspike (2009)\n"),
        ]
        for tag, txt in content:
            text.insert("end", txt, tag if tag else "")
        text.config(state="disabled")

    # ── Event handlers ──────────────────────────────────────
    def _on_defense_change(self):
        pass

    def _update_site_info(self):
        domain = self.domain_var.get()
        site = next((s for s in SITES if s["name"] == domain), None)
        if not site:
            return
        hsts_str = f"  HSTS: {'✓ Enabled' if site['hsts'] else '✗ Disabled'}"
        age_str  = f"  max-age: {site['hsts_max_age']:,}s" if site["hsts"] else ""
        sens_str = f"  Sensitive data: {'Yes ⚠' if site['sensitive'] else 'No'}"
        self.site_hsts_lbl.config(text=hsts_str + age_str + "\n" + sens_str)
        self._refresh_hsts_cache_display()

    def _do_preload(self):
        domain = self.domain_var.get()
        ok = simulate_hsts_preload(domain)
        if ok:
            self._log(f"🔒 HSTS Preloaded: {domain} — browser will enforce HTTPS on next visit\n", "blocked")
        else:
            self._log(f"ℹ  {domain} does not support HSTS — preload skipped\n", "warn")
        self._refresh_hsts_cache_display()

    def _launch_single_attack(self):
        threading.Thread(target=self._run_attack, args=(1,), daemon=True).start()

    def _launch_burst_attack(self):
        n = self.burst_var.get()
        threading.Thread(target=self._run_attack, args=(n,), daemon=True).start()

    def _run_attack(self, count):
        self.attack_btn.config(state="disabled")
        self.burst_btn.config(state="disabled")
        self.status_dot.config(fg=C["red"])
        self.status_lbl.config(text="⚡  Attack in progress...")

        domain = self.domain_var.get()
        for i in range(count):
            self._log(f"\n{'─'*60}\n", "muted")
            self._log(f"[{i+1}/{count}]  ATTACK → {domain}\n", "header")

            # Show request
            req = fake_http_request(domain, https=False)
            self._log(req, "info")
            self._update_packet_display("req", req)
            time.sleep(self.speed_var.get() * 0.4)

            # Run simulation
            success, reason, cred = attempt_ssl_strip(
                domain, self.hsts_var.get(), self.preload_var.get() or is_hsts_cached(domain)
            )

            # Show response
            resp = fake_response_headers(domain, stripped=success)
            self._update_packet_display("resp", resp)

            # Log result
            tag = "success" if success else "blocked"
            self._log(f"  RESULT: {reason}\n", tag)

            if cred:
                cred_str = f"  💀 CREDENTIAL STOLEN: {cred[0]} / {cred[1]}\n"
                self._log(cred_str, "cred")
                self._append_cred(cred)

            self._refresh_hsts_cache_display()
            self._update_stats_display()
            time.sleep(self.speed_var.get())

        self.attack_btn.config(state="normal")
        self.burst_btn.config(state="normal")
        self.status_dot.config(fg=C["green"])
        self.status_lbl.config(text=f"Last run: {count} attempt(s) completed — see log below")

    def _reset_all(self):
        reset_stats()
        self._log_clear()
        self._packet_clear()
        self._refresh_hsts_cache_display()
        self._update_stats_display()
        self.status_lbl.config(text="Simulation Reset — ready for new run")
        self.status_dot.config(fg=C["green"])

    # ── Helpers ─────────────────────────────────────────────
    def _log(self, msg, tag=""):
        self.log_text.config(state="normal")
        if tag:
            self.log_text.insert("end", msg, tag)
        else:
            self.log_text.insert("end", msg)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _log_clear(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def _update_packet_display(self, which, content):
        widget = self.req_text if which == "req" else self.resp_text
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", content)
        widget.config(state="disabled")

    def _packet_clear(self):
        for w in (self.req_text, self.resp_text):
            w.config(state="normal")
            w.delete("1.0", "end")
            w.config(state="disabled")

    def _append_cred(self, cred):
        self.cred_text.config(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.cred_text.insert("end", f"[{ts}]  Email: {cred[0]}   Password: {cred[1]}\n")
        self.cred_text.see("end")
        self.cred_text.config(state="disabled")

    def _refresh_hsts_cache_display(self):
        self.hsts_cache_text.config(state="normal")
        self.hsts_cache_text.delete("1.0", "end")
        if not HSTS_CACHE:
            self.hsts_cache_text.insert("end", "  (empty — no sites visited over HTTPS yet)")
        else:
            for domain, exp in HSTS_CACHE.items():
                remaining = max(0, int(exp - time.time()))
                self.hsts_cache_text.insert("end", f"  ✓ {domain}\n    expires in: {remaining}s\n")
        self.hsts_cache_text.config(state="disabled")

    def _update_stats_display(self):
        s = ATTACK_STATS
        n_creds = len(s["intercepted_creds"])
        self.stat_cards["attempts"].config(text=str(s["attempts"]))
        self.stat_cards["success"].config(text=str(s["success"]))
        self.stat_cards["blocked"].config(text=str(s["blocked"]))
        self.stat_cards["intercepted"].config(text=str(n_creds))
        self._draw_bar_chart()

    def _draw_bar_chart(self):
        c = self.bar_canvas
        c.delete("all")
        cw = c.winfo_width() or 600
        ch = 160
        s = ATTACK_STATS
        data = [
            ("Succeeded",    s["success"],   C["red"]),
            ("Blocked",      s["blocked"],   C["green"]),
            ("Creds stolen", len(s["intercepted_creds"]), C["yellow"]),
        ]
        total = max(s["attempts"], 1)
        bar_w = 60
        gap   = (cw - len(data) * bar_w) // (len(data) + 1)
        max_h = ch - 40
        for i, (label, val, col) in enumerate(data):
            x = gap + i * (bar_w + gap)
            bar_h = int((val / total) * max_h) if total > 0 else 0
            y0 = ch - 24
            y1 = y0 - bar_h
            # Background bar
            c.create_rectangle(x, 20, x + bar_w, y0, fill=C["border"], outline="")
            # Value bar
            if bar_h > 0:
                c.create_rectangle(x, y1, x + bar_w, y0, fill=col, outline="")
            # Label
            c.create_text(x + bar_w // 2, ch - 10, text=label,
                          fill=C["muted"], font=("Consolas", 8), anchor="s")
            c.create_text(x + bar_w // 2, max(y1 - 6, 14), text=str(val),
                          fill=col, font=("Consolas", 10, "bold"))


# ─────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SSLStripSimApp()
    app.mainloop()
