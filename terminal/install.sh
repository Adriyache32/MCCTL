#!/bin/bash
set -e
INSTALL_DIR="${HOME}/.local/share/mcctl"
BIN_DIR="${HOME}/.local/bin"

echo "=== MCCTL - Minecraft Console Terminal ==="
echo "Instalando..."

mkdir -p "$INSTALL_DIR" "$BIN_DIR"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/mcctl.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/version.txt" "$INSTALL_DIR/"

cat > "$BIN_DIR/mcctl" << 'EOF'
#!/bin/bash
exec python3 "${HOME}/.local/share/mcctl/mcctl.py"
EOF

chmod +x "$BIN_DIR/mcctl"

if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo ""
    echo "  Anade ${BIN_DIR} a tu PATH si no esta:"
    echo "    echo 'export PATH=\"\$PATH:${BIN_DIR}\"' >> ~/.zshrc"
    echo "    source ~/.zshrc"
fi

echo ""
echo "Instalado! Ejecuta: mcctl"
echo ""
