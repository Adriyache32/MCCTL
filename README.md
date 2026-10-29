# MCCTL 📊

> Panel de monitoreo y administración para servidores Minecraft. RCON + GUI (Textual) + Terminal + Docker.

## ✨ Características

- **RCON Manager**: Conexión segura, comandos con historial, autocompletado
- **GUI Terminal (Textual)**: Dashboard en tiempo real, logs, métricas, players online
- **CLI completo**: `mcctl status`, `mcctl cmd`, `mcctl logs`, `mcctl backup`
- **Docker ready**: `docker run -d -p 25575:25575 adriyache32/mcctl`
- **Multi-servidor**: Gestiona varios servidores desde una instancia
- **Alertas**: Discord/Telegram/Email por eventos (crash, players, recursos)

## 🚀 Instalación

```bash
# Pip
pip install mcctl

# Docker
docker run -d \
  --name mcctl \
  -e RCON_HOST=localhost \
  -e RCON_PORT=25575 \
  -e RCON_PASSWORD=${RCON_PASSWORD} \
  -p 8080:8080 \
  adriyache32/mcctl

# Desde fuente
git clone https://github.com/Adriyache32/MCCTL.git
cd MCCTL && pip install -e .
```

## ⚙️ Configuración

```yaml
# ~/.config/mcctl/config.yaml
servers:
  survival:
    host: "localhost"
    port: 25575
    password: "${RCON_PASSWORD_SURVIVAL}"
  creative:
    host: "192.168.1.50"
    port: 25575
    password: "${RCON_PASSWORD_CREATIVE}"

alerts:
  discord_webhook: "${DISCORD_WEBHOOK}"
  telegram_bot: "${TELEGRAM_BOT_TOKEN}"
  telegram_chat: "${TELEGRAM_CHAT_ID}"

monitoring:
  interval: 30  # segundos
  metrics: [cpu, memory, players, tps]
```

## 📸 Demo

![MCCTL Demo](assets/demo.gif)

## 🖥️ Uso CLI

```bash
mcctl list                    # Listar servidores
mcctl connect survival        # Conectar RCON interactivo
mcctl cmd survival "say Hola" # Enviar comando
mcctl status survival         # Estado + métricas
mcctl logs survival --follow  # Logs en tiempo real
mcctl backup survival         # Backup mundo
mcctl gui                     # Dashboard Textual
```

## 🏗️ Arquitectura

```
mcctl/
├── cli.py              # Entry point (Click)
├── core/
│   ├── rcon.py         # Cliente RCON asyncio
│   ├── server.py       # Modelo servidor + estado
│   ├── monitor.py      # Métricas + alertas
│   └── backup.py       # Backup mundos
├── tui/
│   ├── app.py          # Textual App
│   ├── dashboard.py    # Dashboard principal
│   ├── logs.py         # Visor logs
│   └── players.py      # Lista players
└── packaging/
    ├── Dockerfile
    ├── pyproject.toml
    └── spec/
```

## 🤝 Contribuir

Ver [CONTRIBUTING.md](CONTRIBUTING.md)

## 📄 Licencia

MIT — ver [LICENSE](LICENSE)

---

**¿Útil? ⭐ Star ayuda a mantener el proyecto.**
