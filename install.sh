#!/bin/bash
# Instalador automático de dependencias

echo "[*] Instalando dependencias..."
sudo apt update && sudo apt install -y aircrack-ng hcxdumptool hashcat wifiphisher

echo "[*] Instalación completada. Ejecuta ./start.sh para iniciar la herramienta."
