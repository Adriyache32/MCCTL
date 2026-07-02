# MCCTL - Minecraft Console Terminal

Panel de monitoreo y administracion para servidores Minecraft.

**Terminal** (curses) — App retro con interfaz de consola
**GUI Desktop** (Tkinter) — App liviana para tener abierta mientras jugas

## Caracteristicas

- Monitoreo en vivo de jugadores, TPS, RAM, version
- Deteccion de actividad sospechosa (/gamemode, /op, exploits, etc.)
- Alertas por severidad (CRITICA, ALTA, MEDIA, BAJA)
- Consola RCON integrada
- Control de servidores locales (start/stop/restart)
- Whitelist detection
- Scroll de logs en tiempo real
- Soporte para servidores locales y remotos

## Instalacion rapida

### Terminal
```bash
git clone https://github.com/Adriyache32/MCCTL.git
cd MCCTL/terminal
bash install.sh
mcctl
```

O directo:
```bash
python3 terminal/mcctl.py
```

### GUI Desktop
```bash
python3 gui/mcctl-gui.py
```

## Requisitos

- Linux (solo)
- Python 3.7+
- Tkinter (para GUI, viene con Python en la mayoria de distros)

## RCON

Para control remoto necesitas en `server.properties`:
```
enable-rcon=true
rcon.password=tu_password
rcon.port=25575
```

## Controles (Terminal)

| Tecla | Accion |
|-------|--------|
| `↑↓` | Navegar servidores |
| `a` | Anadir servidor |
| `d` | Eliminar servidor |
| `c` | Consola RCON |
| `r` | Refrescar |
| `s` | Iniciar servidor (local) |
| `x` | Detener servidor |
| `v` | Ver alertas |
| `?` | Ayuda |
| `q` | Salir |
