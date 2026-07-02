#!/bin/bash
# MCCTL - Instalador completo
set -e
echo "=== MCCTL - Minecraft Console Panel ==="
echo "1) Terminal (curses)"
echo "2) GUI Desktop (Tkinter)"
echo "3) Ambos"
read -p "Selecciona (1/2/3): " opt

case $opt in
  1) bash terminal/install.sh ;;
  2) echo "Ejecuta: python3 gui/mcctl-gui.py" ;;
  3) bash terminal/install.sh
     echo "GUI: python3 gui/mcctl-gui.py" ;;
  *) echo "Opcion invalida" ;;
esac
