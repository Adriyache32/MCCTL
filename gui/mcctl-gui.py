#!/usr/bin/env python3
"""
MCCTL-GUI - Minecraft Console Panel
App de escritorio liviana para monitorear servers (Linux)
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json, threading, time, subprocess, os, socket, struct, re, signal
from pathlib import Path
from datetime import datetime

VERSION = "1.0.g"
CONFIG_DIR = Path.home() / ".config" / "mcctl"
CONFIG_FILE = CONFIG_DIR / "servers.json"

# ─── RCON ────────────────────────────────────────────────

class RCON:
    def __init__(self, host, port=25575, password=""):
        self.host = host; self.port = port; self.password = password
        self.sock = None; self.authed = False

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(4)
            self.sock.connect((self.host, self.port))
            return self._auth()
        except Exception as e:
            return False, str(e)

    def _send(self, ptype, payload):
        if not self.sock: return None
        req_id = int(time.time() * 1000) & 0x7fffffff
        data = struct.pack('<ii', req_id, ptype) + payload.encode('utf8') + b'\x00\x00'
        pad = struct.pack('<i', len(data))
        try:
            self.sock.sendall(pad + data)
            resp_len = struct.unpack('<i', self.sock.recv(4))[0]
            resp_data = b''
            while len(resp_data) < resp_len:
                chunk = self.sock.recv(resp_len - len(resp_data))
                if not chunk: break
                resp_data += chunk
            if len(resp_data) >= 10:
                rid, rtype = struct.unpack('<ii', resp_data[:8])
                rtext = resp_data[8:-2].decode('utf8', errors='replace')
                return rid, rtype, rtext
            return None
        except: return None

    def _auth(self):
        r = self._send(3, self.password)
        if r and r[1] == 2:
            self.authed = True
            return True, "OK"
        self.authed = False
        return False, "Password incorrecta"

    def command(self, cmd):
        if not self.authed:
            ok, _ = self._auth()
            if not ok: return None
        r = self._send(2, cmd)
        return r[2] if r else None

    def close(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None; self.authed = False

# ─── DETECTOR ────────────────────────────────────────────

SUSPICIOUS = [
    (r'/gamemode\s+\w+', 'ALTA', 'Gamemode change'),
    (r'/gm\s+\d', 'ALTA', 'Gamemode shortcut'),
    (r'/op\s+\w+', 'CRITICA', 'Operator attempt'),
    (r'/deop\s+\w+', 'CRITICA', 'Deop attempt'),
    (r'/give\s+\w+\s+\w+', 'ALTA', 'Give command'),
    (r'/i\s+\w+', 'MEDIA', 'Give shortcut'),
    (r'/ban\s+\w+', 'ALTA', 'Ban command'),
    (r'/ban-ip\s+', 'ALTA', 'IP Ban'),
    (r'/pardon\s+\w+', 'MEDIA', 'Unban'),
    (r'/stop', 'CRITICA', 'Server stop'),
    (r'/reload', 'MEDIA', 'Server reload'),
    (r'//\w+', 'MEDIA', 'WorldEdit'),
    (r'/forceload\s+', 'MEDIA', 'Forceload chunks'),
    (r'/kill\s+@', 'ALTA', 'Mass kill'),
    (r'/effect\s+@', 'MEDIA', 'Mass effect'),
    (r'/tp\s+@', 'MEDIA', 'Mass teleport'),
]

EXPLOITS = [
    (r'Disconnecting.*Spam', 'MEDIA', 'Spam detection'),
    (r"Can't keep up", 'BAJA', 'Server lag'),
    (r'NullPointerException', 'BAJA', 'Server error'),
    (r'Bad packet', 'MEDIA', 'Corrupt packet'),
    (r'UUID.*already connected', 'MEDIA', 'Duplicate UUID'),
    (r'BookEdit|book too large', 'MEDIA', 'Book exploit'),
    (r'Internal Exception', 'BAJA', 'Connection error'),
]

class Detector:
    def __init__(self):
        self.alerts = []
        self.players = {}
        self._lock = threading.Lock()

    def analyze(self, line, server):
        alerts = []
        # Chat
        m = re.search(r'<(.*?)>\s*(.*)', line)
        if m:
            p, msg = m.group(1), m.group(2)
            self._track(p, "Chateando", msg)
            for pat, sev, desc in SUSPICIOUS:
                if re.search(pat, msg, re.IGNORECASE):
                    alerts.append((sev, server, f"{p}: {desc} ({msg[:50]})"))
        # Commands
        m = re.search(r'(\w+)\s*issued server command:\s*(.*)', line)
        if m:
            p, cmd = m.group(1), m.group(2)
            self._track(p, "Comandos", cmd)
            for pat, sev, desc in SUSPICIOUS:
                if re.search(pat, cmd, re.IGNORECASE):
                    alerts.append((sev, server, f"{p}: {desc} ({cmd[:50]})"))
        # Join/Leave
        m = re.search(r'(\w+)\s+joined the game', line)
        if m:
            self._track(m.group(1), "Conectado", "")
        m = re.search(r'(\w+)\s+left the game', line)
        if m:
            self._track(m.group(1), "Desconectado", "")
        # Death
        m = re.search(r'(\w+)\s*(was|died|blew|hit|fell|drowned)', line)
        if m:
            self._track(m.group(1), "Combate/Muerte", line[:60])
        # Advancement
        m = re.search(r'(\w+)\s*has made the advancement', line)
        if m:
            self._track(m.group(1), "Avance", line[:60])
        # Exploits
        for pat, sev, desc in EXPLOITS:
            if re.search(pat, line, re.IGNORECASE):
                alerts.append((sev, server, f"{desc}: {line[:80]}"))
                break
        # TPS
        m = re.search(r'Overall\s*:\s*([\d.]+)', line)
        if m and float(m.group(1)) < 10:
            alerts.append(('ALTA', server, f"TPS bajo: {m.group(1)}"))

        with self._lock:
            ts = datetime.now().strftime("%H:%M:%S")
            for sev, sv, desc in alerts:
                self.alerts.append((ts, sev, sv, desc))
            self.alerts = self.alerts[-200:]

        return alerts

    def _track(self, player, action, detail):
        self.players[player] = (action, detail, time.time())

    def get_player_activity(self, player):
        if player in self.players:
            act, det, t = self.players[player]
            mins = int((time.time() - t) // 60)
            return act, det, mins
        return "Inactivo", "", 0

    def clean_players(self, keep_names):
        for p in list(self.players.keys()):
            if p not in keep_names:
                act, _, t = self.players[p]
                if time.time() - t > 600:
                    del self.players[p]

# ─── SERVER MANAGER ──────────────────────────────────────

class ServerMan:
    def __init__(self, config):
        self.config = config
        self.detector = Detector()
        self.rcons = {}
        self.info_cache = {}
        self.log_bufs = {}
        self.log_threads = {}
        self._stop_logs = {}
        self._lock = threading.Lock()

    def get_servers(self):
        return self.config.get("servers", [])

    def add(self, name, host, port=25565, rp=25575, rpass="", local=False, ldir=""):
        s = self.get_servers()
        s.append({"name": name, "host": host, "port": port,
                  "rcon_port": rp, "rcon_pass": rpass,
                  "local": local, "local_dir": ldir})
        self.config["servers"] = s
        self._save()

    def remove(self, idx):
        s = self.get_servers()
        if 0 <= idx < len(s):
            n = s[idx]["name"]
            if n in self.rcons:
                try: self.rcons[n].close()
                except: pass
                del self.rcons[n]
            if n in self.log_threads:
                self._stop_logs[n] = True
                del self.log_threads[n]
            s.pop(idx)
            self.config["servers"] = s
            self._save()
            return True
        return False

    def _save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=2)

    def connect_rcon(self, name):
        s = self.get_servers()
        sv = next((x for x in s if x["name"] == name), None)
        if not sv: return False
        if name in self.rcons:
            try: self.rcons[name].close()
            except: pass
        r = RCON(sv["host"], sv["rcon_port"], sv["rcon_pass"])
        ok, _ = r.connect()
        if ok:
            self.rcons[name] = r
        return ok

    def rcon(self, name, cmd):
        if name not in self.rcons or not self.rcons[name].authed:
            if not self.connect_rcon(name):
                return None
        return self.rcons[name].command(cmd)

    def get_info(self, name):
        s = self.get_servers()
        sv = next((x for x in s if x["name"] == name), None)
        if not sv: return {}
        res = {"online": False, "players": "?", "max": "?",
               "version": "?", "tps": "?", "ram": "?",
               "whitelist": "?", "player_list": [], "motd": ""}

        r = self.rcons.get(name)
        if r and r.authed:
            resp = r.command("list")
            if resp:
                m = re.search(r'There are (\d+) of a max of (\d+)', resp)
                if m:
                    res["players"] = m.group(1)
                    res["max"] = m.group(2)
                pm = re.search(r'players online:(.*)', resp, re.IGNORECASE)
                if pm:
                    res["player_list"] = [x.strip() for x in pm.group(1).split(",") if x.strip()]
            wl = r.command("whitelist list")
            if wl:
                res["whitelist"] = "ON" if "on" in wl.lower() else "OFF"
            ver = r.command("version")
            if ver:
                m = re.search(r'Running (.+?)(?:\n|$)', ver)
                if m: res["version"] = m.group(1).strip()[:30]
            tps = r.command("tps")
            if tps:
                m = re.search(r'Overall\s*:\s*([\d.]+)', tps)
                if m: res["tps"] = m.group(1)
            res["online"] = True

        if sv.get("local"):
            pid = self._find_pid(sv["local_dir"])
            if pid:
                res["online"] = True
                try:
                    rss = subprocess.check_output(["ps","-o","rss=","-p",str(pid)], text=True).strip()
                    if rss: res["ram"] = f"{int(rss)//1024} MB"
                except: pass
                pf = Path(sv["local_dir"]) / "server.properties"
                if pf.exists():
                    m = re.search(r'white-list=(\w+)', pf.read_text())
                    if m: res["whitelist"] = "ON" if m.group(1)=="true" else "OFF"

        self.info_cache[name] = res
        return res

    def _find_pid(self, d):
        try:
            out = subprocess.check_output(["pgrep","-f","minecraft"], text=True, stderr=subprocess.DEVNULL)
            for pid in out.strip().split():
                try:
                    cmd = Path(f"/proc/{pid}/cmdline").read_text().replace('\0', ' ')
                    if d in cmd or "server.jar" in cmd: return int(pid)
                except: pass
        except: pass
        return None

    def start_local(self, name):
        s = self.get_servers()
        sv = next((x for x in s if x["name"] == name), None)
        if not sv or not sv.get("local"): return "Solo local"
        d = Path(sv["local_dir"])
        for scr in ["start.sh", "run.sh"]:
            if (d / scr).exists():
                subprocess.Popen(["bash", str(d/scr)], cwd=str(d),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
                return "Iniciado"
        jars = list(d.glob("*.jar"))
        if jars:
            subprocess.Popen(["java","-jar",str(jars[0])], cwd=str(d),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
            return "Iniciado (java -jar)"
        return "No hay start.sh ni server.jar"

    def stop(self, name):
        r = self.rcon(name, "stop")
        if r: return "Detenido via RCON"
        s = self.get_servers()
        sv = next((x for x in s if x["name"] == name), None)
        if sv and sv.get("local"):
            pid = self._find_pid(sv["local_dir"])
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                    return "Detenido"
                except: pass
        return "No se pudo detener"

    def start_log(self, name):
        if name in self.log_threads: return
        self._stop_logs[name] = False
        self.log_bufs[name] = []
        self.log_threads[name] = threading.Thread(target=self._log_worker, args=(name,), daemon=True)
        self.log_threads[name].start()

    def _log_worker(self, name):
        s = self.get_servers()
        sv = next((x for x in s if x["name"] == name), None)
        if not sv: return
        if sv.get("local"):
            lf = Path(sv["local_dir"]) / "logs" / "latest.log"
            if not lf.exists(): return
            try:
                with open(lf, "r", errors="replace") as f:
                    f.seek(0, 2)
                    while not self._stop_logs.get(name):
                        line = f.readline()
                        if line:
                            line = line.strip()
                            if line:
                                with self._lock:
                                    self.log_bufs[name].append(line)
                                    if len(self.log_bufs[name]) > 300:
                                        self.log_bufs[name] = self.log_bufs[name][-300:]
                                self.detector.analyze(line, name)
                        else:
                            time.sleep(0.2)
            except: pass
        else:
            while not self._stop_logs.get(name):
                resp = self.rcon(name, "list")
                if resp:
                    with self._lock:
                        self.log_bufs[name].append(f"[{datetime.now().strftime('%H:%M:%S')}] Jugadores: {resp.strip()}")
                time.sleep(5)

    def get_logs(self, name, n=50):
        with self._lock:
            return self.log_bufs.get(name, [])[-n:]

    def stop_log(self, name):
        self._stop_logs[name] = True
        if name in self.log_threads:
            self.log_threads[name] = None

# ─── GUI ─────────────────────────────────────────────────

class StatusBar(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, height=24)
        self.label = tk.Label(self, anchor="w", font=("Consolas", 9),
                               bg="#1a1a2e", fg="#00ff88")
        self.label.pack(fill="x")
        self.pack(fill="x", side="bottom")

    def set(self, text):
        self.label.config(text=text)

class PlayerPanel(tk.Frame):
    def __init__(self, parent, detector):
        super().__init__(parent)
        self.det = detector
        self.data = []
        tk.Label(self, text="JUGADORES", font=("Consolas", 9, "bold"),
                 bg="#1a1a2e", fg="#00ff88").pack(anchor="w")
        self.listbox = tk.Listbox(self, height=8, font=("Consolas", 9),
                                   bg="#16213e", fg="#00ff88",
                                   selectbackground="#0f3460",
                                   relief="flat", highlightthickness=0)
        self.listbox.pack(fill="both", expand=True)

    def update(self, players):
        self.listbox.delete(0, "end")
        for p in players:
            act, det, mins = self.det.get_player_activity(p)
            self.listbox.insert("end", f"  {'●' if mins < 5 else '○'} {p:<16} {act:<14} {mins}m")

class LogPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        tk.Label(self, text="LOGS / ACTIVIDAD", font=("Consolas", 9, "bold"),
                 bg="#1a1a2e", fg="#00ff88").pack(anchor="w")
        self.text = tk.Text(self, height=10, font=("Consolas", 9),
                             bg="#0f3460", fg="#a0a0a0",
                             relief="flat", highlightthickness=0)
        self.text.pack(fill="both", expand=True)
        self.text.config(state="disabled")

    def update(self, lines):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        for line in lines[-40:]:
            tag = "normal"
            if "[CRITICA]" in line: tag = "critica"
            elif "[ALTA]" in line: tag = "alta"
            elif "[MEDIA]" in line: tag = "media"
            self.text.insert("end", line + "\n", tag)
        self.text.see("end")
        self.text.config(state="disabled")

class AlertPanel(tk.Frame):
    def __init__(self, parent, detector):
        super().__init__(parent)
        self.det = detector
        tk.Label(self, text="ALERTAS (0)", font=("Consolas", 9, "bold"),
                 bg="#1a1a2e", fg="#ff4444").pack(anchor="w")
        self.text = tk.Text(self, height=6, font=("Consolas", 9),
                             bg="#1a1a2e", fg="#ff8888",
                             relief="flat", highlightthickness=0)
        self.text.pack(fill="both", expand=True)
        self.text.config(state="disabled")

    def update(self):
        alerts = self.det.alerts[-20:]
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        for ts, sev, sv, desc in reversed(alerts):
            color = {"CRITICA": "#ff4444", "ALTA": "#ffaa00", "MEDIA": "#ffcc00", "BAJA": "#88ccff"}
            c = color.get(sev, "#ffffff")
            self.text.insert("end", f"[{ts}] [{sev}] [{sv}] {desc}\n")
        self.text.see("end")
        self.text.config(state="disabled")


class MCCTLGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("MCCTL - Minecraft Console Panel")
        self.root.geometry("900x650")
        self.root.minsize(700, 500)

        # Dark theme colors
        self.bg = "#1a1a2e"
        self.fg = "#00ff88"
        self.root.configure(bg=self.bg)

        self.config = self._load_config()
        self.man = ServerMan(self.config)
        self.servers = self.man.get_servers()
        self.selected = tk.StringVar()
        self.info_labels = {}
        self.updating = False

        self._build_ui()
        self._load_servers()

        # Start refresh loop
        self._refresh()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _load_config(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            try: return json.loads(CONFIG_FILE.read_text())
            except: pass
        return {"servers": []}

    def _build_ui(self):
        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=self.bg)
        style.configure("TLabel", background=self.bg, foreground=self.fg)
        style.configure("TButton", background="#0f3460", foreground="#00ff88",
                        borderwidth=0, focusthickness=0, font=("Consolas", 9))
        style.map("TButton", background=[("active", "#16213e")])
        style.configure("Treeview", background="#16213e", foreground="#00ff88",
                        fieldbackground="#16213e", rowheight=22)
        style.map("Treeview", background=[("selected", "#0f3460")])

        main = tk.Frame(self.root, bg=self.bg)
        main.pack(fill="both", expand=True, padx=4, pady=4)

        # Top bar
        top = tk.Frame(main, bg=self.bg)
        top.pack(fill="x")
        tk.Label(top, text=f" MCCTL v{VERSION}", font=("Consolas", 12, "bold"),
                 bg=self.bg, fg=self.fg).pack(side="left")
        self.status_label = tk.Label(top, text="○ Sin servidor seleccionado",
                                      font=("Consolas", 10), bg=self.bg, fg="#ff4444")
        self.status_label.pack(side="right", padx=5)

        # Content
        content = tk.Frame(main, bg=self.bg)
        content.pack(fill="both", expand=True, pady=2)

        # Left: Server list
        left = tk.Frame(content, bg=self.bg, width=200)
        left.pack(side="left", fill="y", padx=(0, 2))
        left.pack_propagate(False)

        tk.Label(left, text="SERVIDORES", font=("Consolas", 9, "bold"),
                 bg=self.bg, fg=self.fg).pack(anchor="w")

        self.server_list = tk.Listbox(left, font=("Consolas", 9),
                                       bg="#16213e", fg=self.fg,
                                       selectbackground="#0f3460",
                                       relief="flat", highlightthickness=0,
                                       exportselection=False)
        self.server_list.pack(fill="both", expand=True)
        self.server_list.bind("<<ListboxSelect>>", self._on_select)

        btn_frame = tk.Frame(left, bg=self.bg)
        btn_frame.pack(fill="x", pady=2)
        for txt, cmd in [("+", self._add_dialog), ("-", self._remove_server)]:
            tk.Button(btn_frame, text=txt, command=cmd, font=("Consolas", 9),
                      bg="#0f3460", fg=self.fg, relief="flat", width=3,
                      activebackground="#16213e", cursor="hand2").pack(side="left", padx=1)

        # Right side
        right = tk.Frame(content, bg=self.bg)
        right.pack(side="right", fill="both", expand=True)

        # Info panel
        info_frame = tk.Frame(right, bg="#16213e", relief="flat", bd=1)
        info_frame.pack(fill="x", pady=(0, 2))
        tk.Label(info_frame, text="INFORMACION", font=("Consolas", 9, "bold"),
                 bg="#16213e", fg=self.fg).pack(anchor="w", padx=4)

        self.info_grid = tk.Frame(info_frame, bg="#16213e")
        self.info_grid.pack(fill="x", padx=4, pady=2)
        fields = [
            ("host", "Host:"), ("version", "Version:"), ("tps", "TPS:"),
            ("ram", "RAM:"), ("whitelist", "Whitelist:"), ("players", "Jugadores:"),
        ]
        for key, label in fields:
            r = tk.Frame(self.info_grid, bg="#16213e")
            r.pack(fill="x")
            tk.Label(r, text=label, font=("Consolas", 9), bg="#16213e",
                     fg="#8899aa", width=12, anchor="w").pack(side="left")
            lbl = tk.Label(r, text="?", font=("Consolas", 9, "bold"),
                           bg="#16213e", fg=self.fg, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            self.info_labels[key] = lbl

        # Player panel
        self.player_panel = PlayerPanel(right, self.man.detector)
        self.player_panel.pack(fill="x", pady=(0, 2))

        # Log + Alert
        bottom = tk.Frame(right, bg=self.bg)
        bottom.pack(fill="both", expand=True)
        bottom.grid_columnconfigure(0, weight=3)
        bottom.grid_columnconfigure(1, weight=2)

        log_frame = tk.Frame(bottom, bg="#0f3460")
        log_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 1))
        self.log_panel = LogPanel(log_frame)
        self.log_panel.pack(fill="both", expand=True)

        alert_frame = tk.Frame(bottom, bg=self.bg)
        alert_frame.grid(row=0, column=1, sticky="nsew")
        self.alert_panel = AlertPanel(alert_frame, self.man.detector)
        self.alert_panel.pack(fill="both", expand=True)

        # Controls bar
        controls = tk.Frame(main, bg="#0f3460", height=30)
        controls.pack(fill="x", pady=(2, 0))
        buttons = [
            ("▶ Iniciar", self._start_server),
            ("⏹ Detener", self._stop_server),
            ("🔄 Refrescar", self._refresh),
            ("⌨ Consola", self._console),
            ("❓ Ayuda", self._help),
        ]
        for txt, cmd in buttons:
            tk.Button(controls, text=txt, command=cmd, font=("Consolas", 9),
                      bg="#16213e", fg=self.fg, relief="flat", padx=8,
                      activebackground="#1a1a3e", cursor="hand2").pack(side="left", padx=2, pady=2)

        self.status_bar = StatusBar(main)

        # Console window (hidden)
        self.console_win = None

        # Text tags for log colors
        self.log_panel.text.tag_config("critica", foreground="#ff4444")
        self.log_panel.text.tag_config("alta", foreground="#ffaa00")
        self.log_panel.text.tag_config("media", foreground="#ffcc00")

    def _load_servers(self):
        self.server_list.delete(0, "end")
        for sv in self.servers:
            self.server_list.insert("end", f"  {sv['name']}")
            self.man.start_log(sv["name"])

    def _on_select(self, evt=None):
        sel = self.server_list.curselection()
        if sel:
            idx = sel[0]
            if idx < len(self.servers):
                self.selected.set(str(idx))
                self._update_info()

    def _update_info(self):
        if not self.selected.get():
            self.status_label.config(text="○ Sin servidor", fg="#ff4444")
            return
        idx = int(self.selected.get())
        if idx >= len(self.servers):
            self.status_label.config(text="○ Servidor eliminado", fg="#ff4444")
            return

        sv = self.servers[idx]
        info = self.man.get_info(sv["name"])

        if info.get("online"):
            self.status_label.config(
                text=f"● {info.get('players','?')}/{info.get('max','?')} jug | TPS: {info.get('tps','?')} | RAM: {info.get('ram','?')}",
                fg="#00ff88")
        else:
            self.status_label.config(text="○ OFFLINE", fg="#ff4444")

        self.info_labels["host"].config(text=f"{sv['host']}:{sv['port']}")
        self.info_labels["version"].config(text=info.get("version", "?"))
        self.info_labels["tps"].config(text=info.get("tps", "?"))
        self.info_labels["ram"].config(text=info.get("ram", "?"))
        self.info_labels["whitelist"].config(text=info.get("whitelist", "?"),
                                              fg="#00ff88" if info.get("whitelist") == "ON" else "#ffaa00")
        self.info_labels["players"].config(text=f"{info.get('players','?')}/{info.get('max','?')}")

        pcount = f" ({len(info.get('player_list', []))})"
        self.player_panel.update(info.get("player_list", []))
        logs = self.man.get_logs(sv["name"])
        self.log_panel.update(logs)

    def _refresh(self):
        if self.updating: return
        self.updating = True
        try:
            self._update_info()
            self.alert_panel.update()
            self.status_bar.set(f"Ultima actualizacion: {datetime.now().strftime('%H:%M:%S')}  |  Alertas: {len(self.man.detector.alerts)}")
        finally:
            self.updating = False
        self.root.after(3000, self._refresh)

    def _add_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Anadir servidor")
        dialog.geometry("450x350")
        dialog.configure(bg=self.bg)
        dialog.transient(self.root)
        dialog.grab_set()

        fields = [
            ("Nombre:", "name"),
            ("Host/IP:", "host"),
            ("Puerto:", "port"),
            ("RCON Puerto:", "rport"),
            ("RCON Password:", "rpass"),
            ("Tipo (local/remoto):", "tipo"),
            ("Directorio local:", "ldir"),
        ]
        entries = {}
        for i, (label, key) in enumerate(fields):
            f = tk.Frame(dialog, bg=self.bg)
            f.pack(fill="x", padx=10, pady=2)
            tk.Label(f, text=label, font=("Consolas", 9), bg=self.bg,
                     fg="#8899aa", width=16, anchor="w").pack(side="left")
            e = tk.Entry(f, font=("Consolas", 9), bg="#16213e", fg=self.fg,
                         insertbackground=self.fg, relief="flat")
            e.pack(side="left", fill="x", expand=True)
            entries[key] = e

        entries["port"].insert(0, "25565")
        entries["rport"].insert(0, "25575")
        entries["tipo"].insert(0, "remoto")

        def save():
            data = {k: e.get().strip() for k, e in entries.items()}
            if not data["name"] or not data["host"]:
                messagebox.showerror("Error", "Nombre y Host son requeridos")
                return
            try:
                port = int(data["port"]) if data["port"] else 25565
                rport = int(data["rport"]) if data["rport"] else 25575
            except:
                messagebox.showerror("Error", "Puertos invalidos")
                return
            tipo = "local" if data["tipo"].lower().startswith("l") else "remoto"
            self.man.add(data["name"], data["host"], port, rport,
                         data["rpass"], tipo == "local", data["ldir"])
            self.servers = self.man.get_servers()
            self._load_servers()
            self.man.start_log(data["name"])
            dialog.destroy()

        btn_f = tk.Frame(dialog, bg=self.bg)
        btn_f.pack(pady=10)
        tk.Button(btn_f, text="Guardar", command=save,
                  font=("Consolas", 9), bg="#0f3460", fg=self.fg,
                  relief="flat", padx=15, cursor="hand2").pack(side="left", padx=5)
        tk.Button(btn_f, text="Cancelar", command=dialog.destroy,
                  font=("Consolas", 9), bg="#3a1a1a", fg="#ff6666",
                  relief="flat", padx=15, cursor="hand2").pack(side="left", padx=5)

    def _remove_server(self):
        if not self.selected.get(): return
        idx = int(self.selected.get())
        if idx >= len(self.servers): return
        name = self.servers[idx]["name"]
        if messagebox.askyesno("Confirmar", f"Eliminar '{name}'?"):
            self.man.remove(idx)
            self.servers = self.man.get_servers()
            self._load_servers()
            self.selected.set("")
            self.status_label.config(text="○ Servidor eliminado", fg="#ff4444")

    def _start_server(self):
        if not self.selected.get(): return
        idx = int(self.selected.get())
        if idx >= len(self.servers): return
        name = self.servers[idx]["name"]
        msg = self.man.start_local(name)
        self.status_bar.set(msg)
        self.root.after(2000, self._refresh)

    def _stop_server(self):
        if not self.selected.get(): return
        idx = int(self.selected.get())
        if idx >= len(self.servers): return
        name = self.servers[idx]["name"]
        msg = self.man.stop(name)
        self.status_bar.set(msg)
        self.root.after(2000, self._refresh)

    def _console(self):
        if not self.selected.get():
            messagebox.showinfo("Info", "Selecciona un servidor primero")
            return
        idx = int(self.selected.get())
        if idx >= len(self.servers): return
        name = self.servers[idx]["name"]

        if self.console_win and self.console_win.winfo_exists():
            self.console_win.lift()
            return

        self.console_win = tk.Toplevel(self.root)
        self.console_win.title(f"Consola RCON - {name}")
        self.console_win.geometry("650x400")
        self.console_win.configure(bg=self.bg)
        self.console_win.transient(self.root)

        out = tk.Text(self.console_win, font=("Consolas", 10),
                      bg="#0f3460", fg="#a0ffa0", relief="flat", highlightthickness=0)
        out.pack(fill="both", expand=True, padx=4, pady=(4, 0))
        out.insert("end", f"[MCCTL] Conectado a {name}\n")
        out.insert("end", "[MCCTL] Escribe comandos sin / (ej: list, tps, help)\n")
        out.config(state="disabled")

        inp_frame = tk.Frame(self.console_win, bg=self.bg)
        inp_frame.pack(fill="x", padx=4, pady=4)

        tk.Label(inp_frame, text="$", font=("Consolas", 10, "bold"),
                 bg=self.bg, fg=self.fg).pack(side="left")
        entry = tk.Entry(inp_frame, font=("Consolas", 10), bg="#16213e",
                          fg=self.fg, insertbackground=self.fg, relief="flat")
        entry.pack(side="left", fill="x", expand=True)
        entry.focus()

        def send_cmd():
            cmd = entry.get().strip()
            if not cmd: return
            entry.delete(0, "end")
            out.config(state="normal")
            out.insert("end", f"\n> /{cmd}\n")
            resp = self.man.rcon(name, cmd)
            if resp is None:
                out.insert("end", "  [RCON Error] No conectado\n")
            else:
                for line in resp.split("\n"):
                    out.insert("end", f"  {line}\n")
            out.see("end")
            out.config(state="disabled")

        entry.bind("<Return>", lambda e: send_cmd())

    def _help(self):
        msg = """MCCTL - Minecraft Console Panel v1.0

Como usar:
  1. Presiona + para anadir un servidor
  2. Necesitas IP, puerto RCON (25575) y password
  3. Seleccionalo en la lista para ver info en vivo

Detecciones:
  - Comandos sospechosos (/gamemode, /op, /give...)
  - Exploits y vulnerabilidades
  - Caidas de TPS
  - Actividad de cada jugador

RCON:
  server.properties: enable-rcon=true
                     rcon.password=tu_password
                     rcon.port=25575

Consola:
  Escribe comandos sin / (list, tps, whitelist)
"""
        messagebox.showinfo("Ayuda MCCTL", msg)

    def _on_close(self):
        for sv in self.servers:
            self.man.stop_log(sv["name"])
            if sv["name"] in self.man.rcons:
                try: self.man.rcons[sv["name"]].close()
                except: pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ─── MAIN ─────────────────────────────────────────────────

def main():
    app = MCCTLGUI()
    app.run()

if __name__ == "__main__":
    main()
