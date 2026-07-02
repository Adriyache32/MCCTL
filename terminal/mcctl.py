#!/usr/bin/env python3
"""
MCCTL - Minecraft Console Terminal
Panel de administracion para servidores Minecraft (solo Linux)
Estilo retro curses como AI-Launcher-Pro
"""

import curses, time, subprocess, os, sys, json, socket, struct, threading, re
import signal, shutil, urllib.request, textwrap
from pathlib import Path
from datetime import datetime

VERSION = "1.0.b"
CONFIG_DIR = Path.home() / ".config" / "mcctl"
CONFIG_FILE = CONFIG_DIR / "servers.json"
GIT_REPO = "Adriyache32/MCCTL"

# ─── RCON Protocol ────────────────────────────────────────────

class RCON:
    def __init__(self, host, port=25575, password=""):
        self.host = host; self.port = port; self.password = password
        self.sock = None; self.authed = False

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
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
            return True, "Autenticado"
        self.authed = False
        return False, "Password RCON incorrecta"

    def command(self, cmd):
        if not self.authed:
            ok, msg = self._auth()
            if not ok: return f"[RCON Error] {msg}"
        r = self._send(2, cmd)
        if r: return r[2]
        return "[RCON Error] Sin respuesta"

    def close(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None; self.authed = False

# ─── Log Analyzer & Detector ──────────────────────────────

SUSPICIOUS_PATTERNS = [
    (r'/gamemode\s+\w+', 'ALTA', 'Cambio de gamemode'),
    (r'/gm\s+\d', 'ALTA', 'Cambio de gamemode (abrev)'),
    (r'/op\s+\w+', 'CRITICA', 'Intento de operador'),
    (r'/deop\s+\w+', 'CRITICA', 'Remover operador'),
    (r'/give\s+\w+\s+\w+', 'ALTA', 'Comando give'),
    (r'/i\s+\w+', 'MEDIA', 'Comando i (give)'),
    (r'/ban\s+\w+', 'ALTA', 'Comando ban'),
    (r'/ban-ip\s+', 'ALTA', 'Ban por IP'),
    (r'/pardon\s+\w+', 'MEDIA', 'Unban'),
    (r'/stop', 'CRITICA', 'Deteniendo servidor'),
    (r'/reload', 'MEDIA', 'Recargando servidor'),
    (r'//\w+', 'MEDIA', 'WorldEdit command'),
    (r'/forceload\s+', 'MEDIA', 'Forceload chunks'),
    (r'/kill\s+@', 'ALTA', 'Kill masivo'),
    (r'/effect\s+@', 'MEDIA', 'Efecto masivo'),
    (r'/summon\s+\w+', 'BAJA', 'Summon entidad'),
    (r'/fill\s+~', 'BAJA', 'Fill command'),
    (r'/setblock\s+~', 'BAJA', 'Setblock command'),
    (r'/clone\s+~', 'BAJA', 'Clone command'),
    (r'/tp\s+@', 'MEDIA', 'TP masivo'),
    (r'/spreadplayers', 'MEDIA', 'Spread players'),
    (r'/whitelist\s+on', 'BAJA', 'Whitelist activada'),
    (r'/whitelist\s+off', 'BAJA', 'Whitelist desactivada'),
    (r'/difficulty\s+peaceful', 'BAJA', 'Dificultad peaceful'),
]

EXPLOIT_PATTERNS = [
    (r'Disconnecting.*Spam|kick.*spam', 'MEDIA', 'Posible spam/kick'),
    (r'Can\'t keep up!|lag', 'BAJA', 'Server lag detectado'),
    (r'Outdated server!', 'BAJA', 'Version mismatch'),
    (r'Illegal character', 'MEDIA', 'Caracter ilegal en chat'),
    (r'NullPointerException', 'BAJA', 'NullPointer en server'),
    (r'StackOverflowError', 'BAJA', 'Stack overflow en server'),
    (r'Bad packet', 'MEDIA', 'Paquete corrupto'),
    (r'Internal Exception', 'BAJA', 'Excepcion interna'),
    (r'UUID.*already connected', 'MEDIA', 'UUID duplicado'),
    (r'Timeout', 'BAJA', 'Timeout'),
    (r'BookEdit|book too large', 'MEDIA', 'Posible exploit de libros'),
    (r'signed book', 'BAJA', 'Libro firmado'),
    (r'Chunk.*load.*fail', 'BAJA', 'Fallo carga de chunks'),
    (r'Plugin.*error|Error.*plugin', 'BAJA', 'Error de plugin'),
]

class LogDetector:
    def __init__(self):
        self.alerts = []
        self.player_actions = {}
        self.tps_values = []
        self.max_alerts = 100
        self._lock = threading.Lock()

    def analyze_line(self, line, server_name):
        alerts = []
        line_lower = line.lower()

        # Detect chat
        chat_m = re.search(r'<(.*?)>\s*(.*)', line)
        if chat_m:
            player, msg = chat_m.group(1), chat_m.group(2)
            self._track_action(player, "chat", msg)
            # Check for suspicious commands in chat
            for pat, sev, desc in SUSPICIOUS_PATTERNS:
                if re.search(pat, msg, re.IGNORECASE):
                    alert = f"[{sev}] [{server_name}] {player}: {desc} ({msg})"
                    alerts.append(alert)

        # Detect player commands (Spigot/Paper format)
        cmd_m = re.search(r'(\w+)\s*issued server command:\s*(.*)', line)
        if cmd_m:
            player, cmd = cmd_m.group(1), cmd_m.group(2)
            self._track_action(player, "command", cmd)
            for pat, sev, desc in SUSPICIOUS_PATTERNS:
                if re.search(pat, cmd, re.IGNORECASE):
                    alert = f"[{sev}] [{server_name}] {player}: {desc} ({cmd})"
                    alerts.append(alert)

        # Detect join/leave
        join_m = re.search(r'(\w+)\s*joined the game', line)
        if join_m:
            self._track_action(join_m.group(1), "join", line)

        leave_m = re.search(r'(\w+)\s*left the game', line)
        if leave_m:
            self._track_action(leave_m.group(1), "leave", line)

        # Detect deaths
        death_m = re.search(r'(\w+)\s*(was|died|blew|hit|fell|drowned|burned|was struck|was shot)', line)
        if death_m:
            self._track_action(death_m.group(1), "death", line.strip())

        # Detect advancements
        adv_m = re.search(r'(\w+)\s*has made the advancement', line)
        if adv_m:
            self._track_action(adv_m.group(1), "advancement", line.strip())

        # Exploit patterns in log
        for pat, sev, desc in EXPLOIT_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                alert = f"[{sev}] [{server_name}] {desc}: {line.strip()[:80]}"
                alerts.append(alert)
                break

        # TPS detection (from /tps command output)
        tps_m = re.search(r'Overall\s*:\s*([\d.]+)', line)
        if tps_m:
            self.tps_values.append(float(tps_m.group(1)))
            if len(self.tps_values) > 20: self.tps_values.pop(0)

        # Detect TPS drops
        if len(self.tps_values) >= 2:
            avg = sum(self.tps_values[-3:]) / min(len(self.tps_values[-3:]), 3)
            if avg < 10 and len(self.tps_values) >= 3:
                alerts.append(f"[ALTA] [{server_name}] TPS CRITICO: {avg:.1f} (posible exploit/lag machine)")

        with self._lock:
            for a in alerts:
                now = datetime.now().strftime("%H:%M:%S")
                self.alerts.append(f"[{now}] {a}")
            if len(self.alerts) > self.max_alerts:
                self.alerts = self.alerts[-self.max_alerts:]

        return alerts

    def _track_action(self, player, action, detail):
        if player not in self.player_actions:
            self.player_actions[player] = []
        self.player_actions[player].append((time.time(), action, detail))
        if len(self.player_actions[player]) > 50:
            self.player_actions[player] = self.player_actions[player][-50:]

    def get_player_last_action(self, player):
        if player in self.player_actions and self.player_actions[player]:
            action = self.player_actions[player][-1]
            elapsed = int(time.time() - action[0])
            return action[1], action[2][:40], elapsed
        return None, None, None

    def get_player_activity_summary(self, player):
        if player not in self.player_actions:
            return "Inactivo"
        actions = [a[1] for a in self.player_actions[player][-10:]]
        if "chat" in actions: return "Chateando"
        if "command" in actions: return "Usando comandos"
        if "death" in actions: return "Combate/Muerte"
        if "advancement" in actions: return "Explorando"
        if "join" in actions: return "Conectado"
        return "Jugando"

    def get_alerts(self, since=0):
        with self._lock:
            return self.alerts[since:]

    def get_alert_count(self):
        with self._lock:
            return len(self.alerts)

# ─── Server Manager ───────────────────────────────────────

class ServerManager:
    def __init__(self, config):
        self.config = config
        self.detector = LogDetector()
        self.rcon_clients = {}
        self.log_threads = {}
        self.server_status = {}
        self.server_info = {}
        self.log_buffers = {}
        self.player_lists = {}
        self.max_log_lines = 500

    def get_servers(self):
        return self.config.get("servers", [])

    def add_server(self, name, host, port=25565, rcon_port=25575, rcon_pass="", local=False, local_dir=""):
        servers = self.get_servers()
        servers.append({
            "name": name, "host": host, "port": port,
            "rcon_port": rcon_port, "rcon_pass": rcon_pass,
            "local": local, "local_dir": local_dir
        })
        self.config["servers"] = servers
        self._save()

    def remove_server(self, idx):
        servers = self.get_servers()
        if 0 <= idx < len(servers):
            name = servers[idx]["name"]
            if name in self.rcon_clients:
                self.rcon_clients[name].close()
                del self.rcon_clients[name]
            servers.pop(idx)
            self.config["servers"] = servers
            self._save()
            return True
        return False

    def _save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=2)

    def connect_rcon(self, name):
        servers = self.get_servers()
        sv = next((s for s in servers if s["name"] == name), None)
        if not sv: return False, "Servidor no encontrado"
        if name in self.rcon_clients:
            try: self.rcon_clients[name].close()
            except: pass
        rcon = RCON(sv["host"], sv["rcon_port"], sv["rcon_pass"])
        ok, msg = rcon.connect()
        if ok:
            self.rcon_clients[name] = rcon
            self.server_status[name] = True
        else:
            self.server_status[name] = False
        return ok, msg

    def rcon_command(self, name, cmd):
        if name not in self.rcon_clients or not self.rcon_clients[name].authed:
            ok, _ = self.connect_rcon(name)
            if not ok: return "[RCON] No conectado"
        return self.rcon_clients[name].command(cmd)

    def get_status(self, name):
        servers = self.get_servers()
        sv = next((s for s in servers if s["name"] == name), None)
        if not sv: return {"online": False, "error": "No existe"}

        result = {"online": False, "players": 0, "max_players": 0,
                  "version": "?", "tps": "?", "ram": "?", "whitelist": "?",
                  "uptime": "?", "player_list": [], "motd": ""}

        # Try RCON for server info
        rcon = self.rcon_clients.get(name)
        if rcon and rcon.authed:
            # Player list
            resp = rcon.command("list")
            if resp:
                m = re.search(r'There are (\d+) of a max of (\d+)', resp)
                if m:
                    result["players"] = int(m.group(1))
                    result["max_players"] = int(m.group(2))
                pm = re.search(r'players online:(.*)', resp, re.IGNORECASE)
                if pm:
                    names = [n.strip() for n in pm.group(1).split(",") if n.strip()]
                    result["player_list"] = names

            # Whitelist status
            wl = rcon.command("/whitelist list")
            if wl and "on" in wl.lower():
                result["whitelist"] = "ON"
            elif wl and "off" in wl.lower():
                result["whitelist"] = "OFF"

            # Version
            ver = rcon.command("/version")
            if ver:
                m = re.search(r'Running (.+?)(?:\n|$)', ver)
                if m: result["version"] = m.group(1).strip()

            # TPS
            tps_r = rcon.command("/tps")
            if tps_r:
                m = re.search(r'Overall\s*:\s*([\d.]+)', tps_r)
                if m: result["tps"] = m.group(1)

            result["online"] = True

        # Local server info (RAM, uptime)
        if sv.get("local"):
            pid = self._find_mc_pid(sv["local_dir"])
            if pid:
                result["online"] = True
                try:
                    # RAM
                    rss = subprocess.check_output(
                        ["ps", "-o", "rss=", "-p", str(pid)], text=True
                    ).strip()
                    if rss:
                        ram_mb = int(rss) // 1024
                        result["ram"] = f"{ram_mb} MB"
                    # Uptime
                    out = subprocess.check_output(
                        ["ps", "-o", "etime=", "-p", str(pid)], text=True
                    ).strip()
                    if out: result["uptime"] = out
                except: pass

                # Check whitelist from server.properties
                prop_file = Path(sv["local_dir"]) / "server.properties"
                if prop_file.exists():
                    try:
                        content = prop_file.read_text()
                        wm = re.search(r'white-list=(\w+)', content)
                        if wm:
                            result["whitelist"] = "ON" if wm.group(1) == "true" else "OFF"
                        vm = re.search(r'(\w+)-online-mode=(\w+)', content)
                        if vm:
                            result["online_mode"] = vm.group(2)
                    except: pass

        self.server_info[name] = result
        return result

    def _find_mc_pid(self, dir_path):
        try:
            out = subprocess.check_output(
                ["pgrep", "-f", f"java.*minecraft"],
                text=True, stderr=subprocess.DEVNULL
            ).strip().split()
            if out:
                for pid in out:
                    try:
                        cmdline = Path(f"/proc/{pid}/cmdline").read_text().replace('\0', ' ')
                        if dir_path in cmdline or "server.jar" in cmdline:
                            return int(pid)
                    except: pass
            # Try screen/tmux sessions
            for sess_cmd in [["screen", "-ls"], ["tmux", "list-sessions"]]:
                try:
                    out = subprocess.check_output(sess_cmd, text=True, stderr=subprocess.DEVNULL)
                    if "minecraft" in out.lower() or dir_path:
                        return None  # running but can't get pid easily
                except: pass
        except: pass
        return None

    def start_server(self, name):
        servers = self.get_servers()
        sv = next((s for s in servers if s["name"] == name), None)
        if not sv or not sv.get("local"): return False, "Solo servidores locales"
        dir_path = Path(sv["local_dir"])
        script = dir_path / "start.sh"
        if not script.exists():
            script = dir_path / "run.sh"
        if not script.exists():
            # Try to find a jar
            jars = list(dir_path.glob("*.jar"))
            if not jars: return False, "No se encuentra start.sh ni server.jar"
            return False, "Crea un start.sh en el directorio del server"

        try:
            subprocess.Popen(
                ["bash", str(script)],
                cwd=str(dir_path),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            return True, "Servidor iniciado"
        except Exception as e:
            return False, str(e)

    def stop_server(self, name):
        # Try RCON first
        resp = self.rcon_command(name, "/stop")
        if resp and "Error" not in resp:
            return True, "Servidor detenido via RCON"

        # Local fallback
        servers = self.get_servers()
        sv = next((s for s in servers if s["name"] == name), None)
        if sv and sv.get("local"):
            pid = self._find_mc_pid(sv["local_dir"])
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                    return True, "Servidor detenido (SIGTERM)"
                except: pass
        return False, "No se pudo detener"

    def restart_server(self, name):
        ok, msg = self.stop_server(name)
        if not ok: return False, msg
        time.sleep(2)
        return self.start_server(name)

    # ── Log streaming ──

    def start_log_stream(self, name):
        if name in self.log_threads and self.log_threads[name].is_alive():
            return
        self.log_buffers[name] = []
        self.log_threads[name] = threading.Thread(
            target=self._log_stream_worker, args=(name,), daemon=True
        )
        self.log_threads[name].start()

    def _log_stream_worker(self, name):
        servers = self.get_servers()
        sv = next((s for s in servers if s["name"] == name), None)
        if not sv: return

        if sv.get("local"):
            # Tail local log file
            log_dir = Path(sv["local_dir"]) / "logs"
            latest = log_dir / "latest.log"
            if not latest.exists():
                # Try finding log in subdirs
                for f in log_dir.glob("*.log"):
                    latest = f
                    break
            if latest.exists():
                try:
                    with open(latest, "r", errors="replace") as f:
                        f.seek(0, 2)  # EOF
                        while True:
                            line = f.readline()
                            if line:
                                line = line.strip()
                                self._add_log_line(name, line)
                                self.detector.analyze_line(line, name)
                            else:
                                time.sleep(0.1)
                            if not self.log_threads.get(name) or not self.log_threads[name].is_alive():
                                break
                except Exception as e:
                    self._add_log_line(name, f"[MCCTL] Error leyendo log: {e}")
        else:
            # Remote: poll via RCON console
            # Note: RCON doesn't give real-time logs. We'll poll for player list
            # and use whatever RCON commands return.
            while True:
                try:
                    resp = self.rcon_command(name, "/list")
                    if resp and "Error" not in resp:
                        self._add_log_line(name, f"[{datetime.now().strftime('%H:%M:%S')}] {resp}")
                    time.sleep(5)
                except:
                    time.sleep(5)
                if not self.log_threads.get(name) or not self.log_threads[name].is_alive():
                    break

    def _add_log_line(self, name, line):
        if name not in self.log_buffers:
            self.log_buffers[name] = []
        self.log_buffers[name].append(line)
        if len(self.log_buffers[name]) > self.max_log_lines:
            self.log_buffers[name] = self.log_buffers[name][-self.max_log_lines:]

    def get_logs(self, name, n=30):
        if name not in self.log_buffers:
            return []
        return self.log_buffers[name][-n:]

    def stop_log_stream(self, name):
        if name in self.log_threads:
            self.log_threads[name] = None

    def get_detector(self):
        return self.detector

# ─── Config ──────────────────────────────────────────────

def load_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"servers": []}

# ─── Curses UI ───────────────────────────────────────────

def sa(scr, y, x, text, *attrs):
    """Safe addstr"""
    h, w = scr.getmaxyx()
    if y < 0 or y >= h: return
    if x < 0: x = 0
    if x >= w: return
    max_w = w - x - 1
    if max_w <= 0: return
    if len(text) > max_w:
        text = text[:max_w]
    try:
        if attrs:
            scr.addstr(y, x, text, *attrs)
        else:
            scr.addstr(y, x, text)
    except curses.error:
        pass

def draw_border(win, title=""):
    h, w = win.getmaxyx()
    if h < 3 or w < 4: return
    try:
        win.attron(curses.color_pair(4))
        win.border()
        if title:
            max_title = w - 4
            if len(title) > max_title:
                title = title[:max_title]
            win.addstr(0, (w - len(title)) // 2, f" {title} ", curses.color_pair(4) | curses.A_BOLD)
        win.attroff(curses.color_pair(4))
    except curses.error:
        pass

def draw_scrollbar(win, total, pos, height):
    if total <= height: return
    _, w = win.getmaxyx()
    bar_h = max(3, height - 2)
    thumb_pos = int((pos / max(1, total - height)) * (bar_h - 1))
    for i in range(bar_h):
        try:
            if i == thumb_pos:
                win.addstr(1 + i, w - 2, "█", curses.color_pair(3))
            else:
                win.addstr(1 + i, w - 2, "│", curses.color_pair(4))
        except: pass

def color_for_severity(sev):
    if sev == "CRITICA": return curses.color_pair(1)  # red
    if sev == "ALTA": return curses.color_pair(3)      # yellow
    if sev == "MEDIA": return curses.color_pair(5)     # cyan
    return curses.color_pair(2)                         # green

LOG_COLORS = [
    (r'joined the game', curses.color_pair(2)),
    (r'left the game', curses.color_pair(3)),
    (r'\[\w+\]', curses.color_pair(5)),  # alert levels in brackets
    (r'<[^>]+>', curses.color_pair(2)),  # chat messages
    (r'CRITICA', curses.color_pair(1)),
    (r'ALTA', curses.color_pair(3)),
    (r'MEDIA', curses.color_pair(5)),
    (r'BAJA', curses.color_pair(6)),
    (r'Error|error|Exception|exception', curses.color_pair(1)),
    (r'RCON Error', curses.color_pair(1)),
]

def colorize_line(text):
    for pat, color in LOG_COLORS:
        if re.search(pat, text):
            return color
    return curses.color_pair(0)

def format_elapsed(seconds):
    if seconds < 60: return f"{seconds}s"
    if seconds < 3600: return f"{seconds//60}m"
    return f"{seconds//3600}h {(seconds%3600)//60}m"

class MCCTLApp:
    def __init__(self, scr):
        self.scr = scr
        self.config = load_config()
        self.manager = ServerManager(self.config)
        self.servers = self.manager.get_servers()
        self.selected_server = 0
        self.active_panel = 0  # 0=servers, 1=players, 2=logs, 3=alerts
        self.scroll_log = 0
        self.scroll_alerts = 0
        self.scroll_players = 0
        self.scroll_servers = 0
        self.autorefresh = True
        self.refresh_interval = 2
        self.last_refresh = 0
        self.server_data = {}
        self.show_help = False
        self.console_mode = False
        self.console_input = ""
        self.console_history = []
        self.console_output = []
        self.console_scroll = 0
        self.message = ""
        self.message_time = 0
        self.add_mode = False
        self.add_step = 0
        self.add_data = {}
        self.input_field = ""
        self.input_prompt = ""

        # Init colors
        curses.curs_set(0)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)
        curses.init_pair(6, curses.COLOR_BLUE, -1)
        curses.init_pair(7, curses.COLOR_WHITE, -1)

        # Start log streams for all servers
        for sv in self.servers:
            self.manager.start_log_stream(sv["name"])

        self.running = True

    def set_message(self, msg):
        self.message = msg
        self.message_time = time.time()

    def run(self):
        while self.running:
            try:
                h, w = self.scr.getmaxyx()
                if h < 18 or w < 60:
                    self.scr.clear()
                    sa(self.scr, h//2, w//2-15, "Terminal muy pequena (min 60x18)", curses.color_pair(1) | curses.A_BOLD)
                    self.scr.refresh()
                    self.scr.timeout(1000)
                    key = self.scr.getch()
                    if key == ord('q'): break
                    continue

                now = time.time()
                if self.autorefresh and now - self.last_refresh > self.refresh_interval:
                    self._refresh_data()
                    self.last_refresh = now

                if self.show_help:
                    self._draw_help()
                elif self.add_mode:
                    self._draw_add_server()
                elif self.console_mode:
                    self._draw_console()
                else:
                    self._draw_main()

                self.scr.timeout(100)
                key = self.scr.getch()
                self._handle_key(key)

            except KeyboardInterrupt:
                break
            except Exception as e:
                self.set_message(f"Error: {e}")
        self._cleanup()

    def _refresh_data(self):
        if self.servers and 0 <= self.selected_server < len(self.servers):
            name = self.servers[self.selected_server]["name"]
            self.server_data = self.manager.get_status(name)

    def _get_selected_server(self):
        if not self.servers: return None
        if self.selected_server >= len(self.servers):
            self.selected_server = len(self.servers) - 1
        if self.selected_server < 0: return None
        return self.servers[self.selected_server]

    def _draw_main(self):
        self.scr.clear()
        h, w = self.scr.getmaxyx()
        sv = self._get_selected_server()

        # ─── Top bar ───
        title = f" MCCTL v{VERSION} "
        status_text = ""
        status_color = curses.color_pair(4)
        if sv:
            sd = self.server_data
            if sd.get("online"):
                status_text = f"● {sd.get('players',0)}/{sd.get('max_players','?')} jug | TPS: {sd.get('tps','?')} | RAM: {sd.get('ram','?')}"
                status_color = curses.color_pair(2)
            else:
                status_text = "○ OFFLINE"
                status_color = curses.color_pair(1)

        bar_text = f"{title}  {status_text}".ljust(w-1)[:w-1]
        try:
            self.scr.addstr(0, 0, bar_text[:w-1], status_color | curses.A_BOLD)
        except: pass
        try:
            self.scr.addstr(0, max(0, w-12), f" q:Salir ", curses.color_pair(4))
        except: pass

        # ─── Left panel: Server list ───
        left_w = max(20, w // 4)
        list_h = h - 4
        # Manual drawing
        panel_y, panel_x = 1, 0
        pw, ph = left_w, list_h

        # Border and title
        self._draw_box(panel_y, panel_x, ph, pw, " SERVIDORES ")

        vis = ph - 2
        servers = self.servers
        for i in range(vis):
            idx = i + self.scroll_servers
            if idx >= len(servers): break
            sv_name = servers[idx]["name"]
            prefix = "○"
            color = curses.color_pair(0)
            if idx == self.selected_server:
                prefix = "▶"
                color = curses.color_pair(2) | curses.A_BOLD
                # highlight bg
                try:
                    self.scr.addstr(panel_y+1+i, panel_x+1, " " * (pw-2), curses.color_pair(2) | curses.A_REVERSE)
                except: pass
            # Truncate name
            disp = f" {prefix} {sv_name}"
            if len(disp) > pw - 3: disp = disp[:pw-4] + "…"
            try:
                self.scr.addstr(panel_y+1+i, panel_x+1, disp, color)
            except: pass

        # Add server button
        add_y = panel_y + ph - 1
        if len(servers) < vis + self.scroll_servers:
            add_y = panel_y + 1 + min(len(servers) - self.scroll_servers, vis)
        if add_y < panel_y + ph - 2:
            try:
                btn = "[+] Anadir servidor"
                if len(btn) > pw - 3: btn = btn[:pw-4]
                self.scr.addstr(add_y, panel_x+1, btn, curses.color_pair(2) | curses.A_DIM)
            except: pass

        draw_scrollbar(self.scr, len(servers), self.scroll_servers, vis)

        # ─── Right panels ───
        right_x = left_w
        right_w = w - right_x
        if right_w < 20: right_w = 20

        if sv:
            sd = self.server_data

            # ── Info panel (top right) ──
            info_h = max(5, h // 3)
            self._draw_box(panel_y, right_x, info_h, right_w, " INFORMACION ")

            info_lines = [
                f"Host: {sv['host']}:{sv['port']}",
                f"Version: {sd.get('version', '?')}",
                f"TPS: {sd.get('tps', '?')}",
                f"RAM: {sd.get('ram', 'No disponible')}",
                f"Whitelist: {sd.get('whitelist', '?')}",
                f"Uptime: {sd.get('uptime', '?')}",
            ]
            if sd.get("online_mode"):
                info_lines.append(f"Online-mode: {sd['online_mode']}")

            for i, line in enumerate(info_lines):
                if i >= info_h - 2: break
                try:
                    display = f" {line}"
                    if len(display) > right_w - 2: display = display[:right_w-3] + "…"
                    self.scr.addstr(panel_y+1+i, right_x+1, display, curses.color_pair(7))
                except: pass

            # ── Players panel ──
            players_y = panel_y + info_h
            players_h = max(4, (h - 4 - info_h) // 2)
            self._draw_box(players_y, right_x, players_h, right_w, " JUGADORES ")

            player_list = sd.get("player_list", [])
            vis_p = players_h - 2
            for i in range(vis_p):
                idx = i + self.scroll_players
                if idx >= len(player_list): break
                pname = player_list[idx]
                activity, detail, elapsed = self.manager.get_detector().get_player_last_action(pname)
                act_summary = self.manager.get_detector().get_player_activity_summary(pname)
                elapsed_str = format_elapsed(elapsed) if elapsed is not None else "?"
                online_dot = "●" if elapsed is not None and elapsed < 300 else "○"
                display = f" {online_dot} {pname:<16} {act_summary:<14} {elapsed_str}"
                if len(display) > right_w - 3: display = display[:right_w-4] + "…"
                try:
                    self.scr.addstr(players_y+1+i, right_x+1, display, curses.color_pair(2) if online_dot == "●" else curses.color_pair(3))
                except: pass

            draw_scrollbar(self.scr, len(player_list), self.scroll_players, vis_p)

            # ── Logs panel ──
            logs_y = players_y + players_h
            logs_h = h - 4 - logs_y
            self._draw_box(logs_y, right_x, logs_h, right_w, " LOGS ")

            logs = self.manager.get_logs(sv["name"], logs_h - 2)
            alerts = self.manager.get_detector()
            alert_count = alerts.get_alert_count()
            if alert_count > 0:
                try:
                    aldisp = f" ⚠ {alert_count} alertas"
                    self.scr.addstr(logs_y, max(0, right_x + right_w - len(aldisp) - 2), aldisp, curses.color_pair(3) | curses.A_BOLD)
                except: pass

            for i in range(logs_h - 2):
                idx = i + self.scroll_log
                if idx >= len(logs): break
                line = logs[idx]
                color = colorize_line(line)
                display = f" {line}"
                # Check if it's an alert line
                if any(sev in line for sev in ["[CRITICA]", "[ALTA]", "[MEDIA]"]):
                    color = colorize_line(line)
                if len(display) > right_w - 3: display = display[:right_w-4] + "…"
                try:
                    self.scr.addstr(logs_y+1+i, right_x+1, display, color)
                except: pass

            draw_scrollbar(self.scr, len(logs), self.scroll_log, logs_h - 2)

        else:
            # No servers
            self._draw_box(panel_y, right_x, h-4, right_w, " BIENVENIDO ")
            msg_lines = [
                "No hay servidores configurados.",
                "",
                "Presiona [a] para anadir tu primer",
                "servidor Minecraft.",
                "",
                "Necesitas:",
                "  • IP del servidor",
                "  • Puerto RCON (default: 25575)",
                "  • Password RCON",
                "",
                "O selecciona 'Local' si el server",
                "esta en esta misma maquina."
            ]
            for i, line in enumerate(msg_lines):
                if i >= h - 6: break
                try:
                    self.scr.addstr(panel_y+1+i, right_x+2, line, curses.color_pair(7) if not line.startswith("  ") else curses.color_pair(5))
                except: pass

        # ─── Bottom bar ───
        bottom_y = h - 1
        controls = []
        if sv:
            controls += ["[c] Consola", "[r] Refrescar", "[a] Anadir"]
            if sv.get("local"):
                controls += ["[s] Start", "[x] Stop"]
            controls += ["[d] Eliminar", "[v] Alertas"]
        else:
            controls = ["[a] Anadir servidor"]

        controls += ["[?] Ayuda"]
        controls_text = "  ".join(controls)
        if len(controls_text) > w - 1:
            controls_text = controls_text[:w-2]
        try:
            self.scr.addstr(bottom_y, 0, controls_text.ljust(w-1)[:w-1], curses.color_pair(4) | curses.A_REVERSE)
        except: pass

        # Message
        if self.message and time.time() - self.message_time < 3:
            try:
                mw = min(len(self.message), w - 4)
                self.scr.addstr(h-2, max(0, w - mw - 2), f" {self.message} ", curses.color_pair(5) | curses.A_BOLD)
            except: pass

        self.scr.noutrefresh()

    def _draw_box(self, y, x, hh, ww, title=""):
        if hh < 2 or ww < 3: return
        try:
            # corners
            self.scr.addch(y, x, curses.ACS_ULCORNER, curses.color_pair(4))
            self.scr.addch(y, x+ww-1, curses.ACS_URCORNER, curses.color_pair(4))
            self.scr.addch(y+hh-1, x, curses.ACS_LLCORNER, curses.color_pair(4))
            self.scr.addch(y+hh-1, x+ww-1, curses.ACS_LRCORNER, curses.color_pair(4))
            # horizontal lines
            for i in range(1, ww-1):
                self.scr.addch(y, x+i, curses.ACS_HLINE, curses.color_pair(4))
                self.scr.addch(y+hh-1, x+i, curses.ACS_HLINE, curses.color_pair(4))
            # vertical lines
            for i in range(1, hh-1):
                self.scr.addch(y+i, x, curses.ACS_VLINE, curses.color_pair(4))
                self.scr.addch(y+i, x+ww-1, curses.ACS_VLINE, curses.color_pair(4))
            if title:
                max_t = ww - 4
                if len(title) > max_t: title = title[:max_t]
                self.scr.addstr(y, x+2, f" {title} ", curses.color_pair(4) | curses.A_BOLD)
        except curses.error:
            pass

    def _draw_help(self):
        self.scr.clear()
        h, w = self.scr.getmaxyx()
        title = " MCCTL - Ayuda "
        try:
            self.scr.addstr(0, (w-len(title))//2, title, curses.color_pair(4) | curses.A_BOLD)
        except: pass

        help_lines = [
            "",
            "PANEL PRINCIPAL:",
            "  ↑/↓        - Navegar servidores",
            "  ←/→        - Cambiar panel (servidores/logs)",
            "  PgUp/PgDn  - Scroll en panel activo",
            "  a          - Anadir servidor",
            "  d          - Eliminar servidor seleccionado",
            "  c          - Consola RCON",
            "  r          - Refrescar datos",
            "  s          - Iniciar servidor (local)",
            "  x          - Detener servidor",
            "  v          - Ver alertas/detecciones",
            "  ?          - Esta ayuda",
            "  q          - Salir",
            "",
            "ANADIR SERVIDOR:",
            "  Tipo: local (misma maquina) o remoto",
            "  RCON: puerto (25575) y password necesarios",
            "  Local: ruta al directorio del servidor",
            "",
            "DETECCIONES:",
            "  El sistema analiza logs en busca de:",
            "  • Comandos sospechosos (/gamemode, /op, /give...)",
            "  • Posibles exploits y vulnerabilidades",
            "  • Caidas de TPS (posible lag machine)",
            "  • Errores del servidor",
            "  • Actividad de jugadores",
            "",
            "RCON:",
            "  Para control remoto necesitas:",
            "  1. server.properties: enable-rcon=true",
            "  2. rcon.password=tu_password",
            "  3. rcon.port=25575",
            "",
            "Presiona cualquier tecla para volver"
        ]
        for i, line in enumerate(help_lines):
            if i >= h - 1: break
            try:
                color = curses.color_pair(4) if line.startswith("  ") else curses.color_pair(7)
                self.scr.addstr(1+i, max(0, (w-50)//2), line, color)
            except: pass

        self.scr.refresh()
        self.scr.getch()
        self.show_help = False

    def _draw_add_server(self):
        self.scr.clear()
        h, w = self.scr.getmaxyx()

        title = " MCCTL - Anadir Servidor "
        try:
            self.scr.addstr(0, (w-len(title))//2, title, curses.color_pair(4) | curses.A_BOLD)
        except: pass

        steps = [
            ("Nombre", "Nombre para identificar el servidor"),
            ("Host/IP", "Direccion IP o dominio"),
            ("Puerto", "Puerto del servidor MC (default: 25565)"),
            ("RCON Puerto", "Puerto RCON (default: 25575)"),
            ("RCON Password", "Password RCON del server.properties"),
            ("Tipo", "local / remoto"),
            ("Directorio Local", "Ruta al dir del server (solo local)"),
        ]

        y = 2
        for i, (label, desc) in enumerate(steps):
            color = curses.color_pair(7)
            prefix = " "
            if i == self.add_step:
                prefix = "▶"
                color = curses.color_pair(2) | curses.A_BOLD
            try:
                self.scr.addstr(y+i, 4, f" {prefix} {label}: ", color)
            except: pass

            if i < self.add_step:
                val = self.add_data.get(label.lower().replace(" ", "_"), "")
                try:
                    self.scr.addstr(y+i, 25, str(val)[:w-30], curses.color_pair(2))
                except: pass
            elif i == self.add_step:
                input_val = self.input_field
                disp = f" {input_val}█" if input_val else " (escribe y Enter) "
                try:
                    self.scr.addstr(y+i, 25, disp[:w-30], curses.color_pair(3) | curses.A_BLINK)
                except: pass

        # Description
        if self.add_step < len(steps):
            _, desc_text = steps[self.add_step]
            try:
                self.scr.addstr(y + len(steps) + 1, 4, f"  {desc_text}", curses.color_pair(5))
            except: pass

        try:
            self.scr.addstr(h-1, 2, " Enter: siguiente  |  Esc: cancelar ", curses.color_pair(4) | curses.A_REVERSE)
        except: pass

        self.scr.refresh()
        # Input handling
        self.scr.timeout(-1)
        while self.add_mode:
            ch = self.scr.getch()
            if ch == 27:  # ESC
                self.add_mode = False
                self.add_step = 0
                self.add_data = {}
                self.input_field = ""
                self.scr.timeout(100)
                curses.curs_set(0)
                break
            elif ch == 10 or ch == ord('\n'):  # Enter
                self._process_add_step()
            elif ch == curses.KEY_BACKSPACE or ch == 127:
                self.input_field = self.input_field[:-1]
            elif 32 <= ch <= 126:
                self.input_field += chr(ch)
            self._draw_add_server()

    def _process_add_step(self):
        labels = ["nombre", "host_ip", "puerto", "rcon_puerto", "rcon_password", "tipo", "directorio_local"]
        keys = ["nombre", "host", "port", "rcon_port", "rcon_pass", "tipo", "local_dir"]

        if self.add_step < len(labels):
            key = keys[self.add_step]
            val = self.input_field.strip()

            if key == "nombre":
                if not val: return
            elif key == "host":
                if not val: return
            elif key == "port":
                try: val = int(val) if val else 25565
                except: val = 25565
            elif key == "rcon_port":
                try: val = int(val) if val else 25575
                except: val = 25575
            elif key == "rcon_pass":
                val = val
            elif key == "tipo":
                val = val.lower() if val else "remoto"
                if val not in ("local", "remoto", "l", "r"):
                    self.input_field = ""
                    return
                val = "local" if val.startswith("l") else "remoto"
            elif key == "local_dir":
                if self.add_data.get("tipo") == "local" and not val:
                    return
                val = val if val else ""

            self.add_data[key] = val
            self.add_step += 1
            self.input_field = ""

            if self.add_step >= len(labels):
                # Save server
                name = self.add_data.get("nombre", "Server")
                host = self.add_data.get("host", "localhost")
                port = int(self.add_data.get("port", 25565))
                rcon_port = int(self.add_data.get("rcon_port", 25575))
                rcon_pass = self.add_data.get("rcon_pass", "")
                tipo = self.add_data.get("tipo", "remoto")
                local_dir = self.add_data.get("local_dir", "")

                self.manager.add_server(name, host, port, rcon_port, rcon_pass, tipo == "local", local_dir)
                self.servers = self.manager.get_servers()
                self.manager.start_log_stream(name)
                self.set_message(f"Servidor '{name}' anadido!")
                self.add_mode = False
                self.add_step = 0
                self.add_data = {}
                self.scr.timeout(100)
                curses.curs_set(0)
        else:
            self.add_mode = False

    def _draw_console(self):
        self.scr.clear()
        h, w = self.scr.getmaxyx()
        sv = self._get_selected_server()

        title = f" MCCTL - Consola RCON: {sv['name'] if sv else 'N/A'} "
        try:
            self.scr.addstr(0, max(0, (w-len(title))//2), title, curses.color_pair(4) | curses.A_BOLD)
            self.scr.addstr(0, w-15, " Esc: salir ", curses.color_pair(4))
        except: pass

        # Output area
        out_h = h - 4
        output = self.console_output
        scroll = self.console_scroll

        for i in range(out_h):
            idx = i + scroll
            if idx >= len(output): break
            line = output[idx]
            display = f" {line}"
            if len(display) > w - 2: display = display[:w-3] + "…"
            try:
                color = curses.color_pair(2) if line.startswith(">") else curses.color_pair(7)
                self.scr.addstr(1+i, 0, display, color)
            except: pass

        draw_scrollbar(self.scr, len(output), scroll, out_h)

        # Input line
        try:
            prompt = " $ "
            self.scr.addstr(h-2, 0, prompt, curses.color_pair(2) | curses.A_BOLD)
            inp_disp = self.console_input
            if len(inp_disp) > w - len(prompt) - 1:
                inp_disp = inp_disp[-(w - len(prompt) - 4):]
            self.scr.addstr(h-2, len(prompt), inp_disp, curses.color_pair(3))
            if len(inp_disp) < w - len(prompt) - 1:
                try:
                    self.scr.addstr(h-2, len(prompt) + len(inp_disp), "█", curses.color_pair(3) | curses.A_BLINK)
                except: pass
        except: pass

        try:
            help_txt = " ↑↓: scroll  |  Tab: historial  |  Enter: enviar  |  Esc: salir "
            self.scr.addstr(h-1, 0, help_txt.ljust(w-1)[:w-1], curses.color_pair(4) | curses.A_REVERSE)
        except: pass

        self.scr.refresh()

        # Input handling
        self.scr.timeout(-1)
        curses.curs_set(1)
        while self.console_mode:
            ch = self.scr.getch()
            if ch == 27:  # ESC
                self.console_mode = False
                self.console_scroll = 0
                self.scr.timeout(100)
                curses.curs_set(0)
                break
            elif ch == 10 or ch == ord('\n'):  # Enter
                cmd = self.console_input.strip()
                if cmd:
                    self.console_output.append(f"> /{cmd}")
                    self.console_history.append(cmd)
                    resp = self.manager.rcon_command(sv["name"], cmd)
                    self.console_output.append(f"  {resp}")
                    if len(self.console_output) > 200:
                        self.console_output = self.console_output[-200:]
                    self.console_scroll = max(0, len(self.console_output) - (h - 4))
                self.console_input = ""
            elif ch == curses.KEY_BACKSPACE or ch == 127:
                self.console_input = self.console_input[:-1]
            elif ch == curses.KEY_UP:
                self.console_scroll = max(0, self.console_scroll - 1)
            elif ch == curses.KEY_DOWN:
                max_scroll = max(0, len(self.console_output) - (h - 4))
                self.console_scroll = min(max_scroll, self.console_scroll + 1)
            elif ch == 9 and self.console_history:  # Tab
                self.console_input = self.console_history[-1]
            elif 32 <= ch <= 126:
                self.console_input += chr(ch)
            self._draw_console()

    def _draw_alerts(self):
        self.scr.clear()
        h, w = self.scr.getmaxyx()
        alerts = self.manager.get_detector().get_alerts()

        title = f" MCCTL - Alertas ({len(alerts)}) "
        try:
            self.scr.addstr(0, max(0, (w-len(title))//2), title, curses.color_pair(4) | curses.A_BOLD)
            self.scr.addstr(0, w-15, " q: volver ", curses.color_pair(4))
        except: pass

        vis = h - 2
        for i in range(vis):
            idx = i + self.scroll_alerts
            if idx >= len(alerts): break
            line = alerts[idx]
            color = curses.color_pair(7)
            if "[CRITICA]" in line: color = curses.color_pair(1) | curses.A_BOLD
            elif "[ALTA]" in line: color = curses.color_pair(3)
            elif "[MEDIA]" in line: color = curses.color_pair(5)
            elif "[BAJA]" in line: color = curses.color_pair(6)

            display = f" {line}"
            if len(display) > w - 2: display = display[:w-3] + "…"
            try:
                self.scr.addstr(1+i, 0, display, color)
            except: pass

        draw_scrollbar(self.scr, len(alerts), self.scroll_alerts, vis)

        self.scr.refresh()
        self.scr.timeout(-1)
        while True:
            ch = self.scr.getch()
            if ch == ord('q') or ch == 27:
                self.scroll_alerts = 0
                break
            elif ch == curses.KEY_UP:
                self.scroll_alerts = max(0, self.scroll_alerts - 1)
            elif ch == curses.KEY_DOWN:
                max_s = max(0, len(alerts) - vis)
                self.scroll_alerts = min(max_s, self.scroll_alerts + 1)
            elif ch == curses.KEY_NPAGE:
                self.scroll_alerts += vis
            elif ch == curses.KEY_PPAGE:
                self.scroll_alerts = max(0, self.scroll_alerts - vis)
            self._draw_alerts()

    def _draw_alert_popup(self):
        alerts = self.manager.get_detector().get_alerts()
        if not alerts:
            self.set_message("No hay alertas")
            return

        # Show last 5 alerts as a quick popup
        h, w = self.scr.getmaxyx()
        popup_h = min(12, h - 4)
        popup_w = min(60, w - 4)
        popup_y = (h - popup_h) // 2
        popup_x = (w - popup_w) // 2

        try:
            win = curses.newwin(popup_h, popup_w, popup_y, popup_x)
            win.clear()
            win.attron(curses.color_pair(4))
            win.border()
            win.attroff(curses.color_pair(4))
            win.addstr(0, 2, " ULTIMAS ALERTAS ", curses.color_pair(4) | curses.A_BOLD)
            win.addstr(popup_h-1, 2, " PgUp/PgDn scroll  q:cerrar ", curses.color_pair(4))

            for i in range(popup_h - 2):
                idx = i + self.scroll_alerts
                if idx >= len(alerts): break
                line = alerts[idx]
                color = curses.color_pair(7)
                if "[CRITICA]" in line: color = curses.color_pair(1) | curses.A_BOLD
                elif "[ALTA]" in line: color = curses.color_pair(3)
                elif "[MEDIA]" in line: color = curses.color_pair(5)
                display = line[:popup_w-4]
                win.addstr(1+i, 2, display, color)

            draw_scrollbar(win, len(alerts), self.scroll_alerts, popup_h - 2)
            win.refresh()

            while True:
                ch = self.scr.getch()
                if ch == ord('q') or ch == 27: break
                elif ch == curses.KEY_UP: self.scroll_alerts = max(0, self.scroll_alerts - 1)
                elif ch == curses.KEY_DOWN:
                    self.scroll_alerts = min(max(0, len(alerts) - popup_h + 2), self.scroll_alerts + 1)
                elif ch == curses.KEY_NPAGE: self.scroll_alerts += popup_h - 2
                elif ch == curses.KEY_PPAGE: self.scroll_alerts = max(0, self.scroll_alerts - popup_h + 2)
                # Redraw
                win.clear()
                win.attron(curses.color_pair(4))
                win.border()
                win.attroff(curses.color_pair(4))
                win.addstr(0, 2, " ULTIMAS ALERTAS ", curses.color_pair(4) | curses.A_BOLD)
                win.addstr(popup_h-1, 2, " PgUp/PgDn scroll  q:cerrar ", curses.color_pair(4))
                for i in range(popup_h - 2):
                    idx = i + self.scroll_alerts
                    if idx >= len(alerts): break
                    line = alerts[idx]
                    color = curses.color_pair(7)
                    if "[CRITICA]" in line: color = curses.color_pair(1) | curses.A_BOLD
                    elif "[ALTA]" in line: color = curses.color_pair(3)
                    elif "[MEDIA]" in line: color = curses.color_pair(5)
                    display = line[:popup_w-4]
                    win.addstr(1+i, 2, display, color)
                draw_scrollbar(win, len(alerts), self.scroll_alerts, popup_h - 2)
                win.refresh()

            del win
        except: pass
        self.scroll_alerts = 0

    def _handle_key(self, key):
        if key == -1: return

        if key == ord('q'):
            self.running = False
            return

        if key == ord('?'):
            self.show_help = True
            return

        if key == ord('a'):
            self.add_mode = True
            self.add_step = 0
            self.add_data = {}
            self.input_field = ""
            return

        if key == ord('v'):
            self._draw_alert_popup()
            return

        if key == ord('c') and self.servers:
            self.console_mode = True
            self.console_input = ""
            self.console_output.append(f"[MCCTL] Conectado a {self.servers[self.selected_server]['name']}")
            self.console_output.append("[MCCTL] Escribe comandos sin / (ej: list, tps, help)")
            return

        if key == ord('r'):
            self._refresh_data()
            self.set_message("Datos refrescados")
            return

        if key == ord('d') and self.servers:
            name = self.servers[self.selected_server]["name"]
            if self.manager.remove_server(self.selected_server):
                self.servers = self.manager.get_servers()
                if self.selected_server >= len(self.servers):
                    self.selected_server = max(0, len(self.servers) - 1)
                self.set_message(f"Servidor '{name}' eliminado")
            return

        if key == ord('s') and self.servers:
            sv = self.servers[self.selected_server]
            if sv.get("local"):
                ok, msg = self.manager.start_server(sv["name"])
                self.set_message(msg)
            else:
                self.set_message("Solo disponible para servidores locales")
            return

        if key == ord('x') and self.servers:
            sv = self.servers[self.selected_server]
            ok, msg = self.manager.stop_server(sv["name"])
            self.set_message(msg)
            return

        # Navigation
        if key == curses.KEY_UP:
            if self.active_panel == 0:  # server list
                self.selected_server = max(0, self.selected_server - 1)
                if self.selected_server < self.scroll_servers:
                    self.scroll_servers = max(0, self.scroll_servers - 1)
                self._refresh_data()
            elif self.active_panel == 1:  # players
                self.scroll_players = max(0, self.scroll_players - 1)
            elif self.active_panel == 2:  # logs
                self.scroll_log = max(0, self.scroll_log - 1)

        elif key == curses.KEY_DOWN:
            if self.active_panel == 0:
                self.selected_server = min(len(self.servers) - 1, self.selected_server + 1)
                h, _ = self.scr.getmaxyx()
                list_h = h - 4
                vis = list_h - 2
                if self.selected_server >= self.scroll_servers + vis:
                    self.scroll_servers += 1
                self._refresh_data()
            elif self.active_panel == 1:
                sv = self._get_selected_server()
                max_players = len(self.server_data.get("player_list", [])) if sv else 0
                self.scroll_players = min(max(0, max_players - 2), self.scroll_players + 1)
            elif self.active_panel == 2:
                sv = self._get_selected_server()
                logs = self.manager.get_logs(sv["name"], 9999) if sv else []
                h, _ = self.scr.getmaxyx()
                log_h = max(3, h - 8)
                self.scroll_log = min(max(0, len(logs) - log_h + 2), self.scroll_log + 1)

        elif key == curses.KEY_LEFT:
            self.active_panel = max(0, self.active_panel - 1)

        elif key == curses.KEY_RIGHT:
            self.active_panel = min(2, self.active_panel + 1)

        elif key == curses.KEY_NPAGE:
            if self.active_panel == 2:
                self.scroll_log += 10
            elif self.active_panel == 1:
                self.scroll_players += 5

        elif key == curses.KEY_PPAGE:
            if self.active_panel == 2:
                self.scroll_log = max(0, self.scroll_log - 10)
            elif self.active_panel == 1:
                self.scroll_players = max(0, self.scroll_players - 5)

    def _cleanup(self):
        for name in list(self.manager.rcon_clients.keys()):
            try: self.manager.rcon_clients[name].close()
            except: pass
        curses.endwin()

def main(scr):
    app = MCCTLApp(scr)
    app.run()

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\nMCCTL cerrado.")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
