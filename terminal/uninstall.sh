#!/bin/bash
echo "Desinstalando MCCTL..."
rm -rf "${HOME}/.local/share/mcctl"
rm -f "${HOME}/.local/bin/mcctl"
rm -rf "${HOME}/.config/mcctl"
echo "MCCTL desinstalado."
