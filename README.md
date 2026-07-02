# MCCTL - Minecraft Console Panel

App de escritorio liviana para monitorear y administrar servidores Minecraft.

## Instalacion

```bash
# Opcion 1: Descargar release
# Ve a https://github.com/Adriyache32/MCCTL/releases
# Descarga MCCTL-v2.0v.tar.gz

tar xzf MCCTL-v2.0v.tar.gz
cd MCCTL
python3 gui/mcctl-gui.py
```

```bash
# Opcion 2: Clonar
git clone https://github.com/Adriyache32/MCCTL.git
cd MCCTL
python3 gui/mcctl-gui.py
```

## Requisitos

- Linux
- Python 3.7+
- Tkinter (viene con Python)

## RCON

En server.properties:
```
enable-rcon=true
rcon.password=tu_password
rcon.port=25575
```
