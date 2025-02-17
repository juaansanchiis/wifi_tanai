#!/bin/bash
# Script de arranque para WiFiAutoPwn

echo "[*] Directorio actual: $(pwd)"

# Verifica que el archivo wifi_auto_pwn.py exista en el directorio actual
if [ ! -f \"wifi_auto_pwn.py\" ]; then
    echo \"[!] Error: No se encontró 'wifi_auto_pwn.py' en el directorio actual.\"
    exit 1
fi

# Define la interfaz por defecto, pero permite pasarla como argumento
INTERFACE=\"wlan0\"
if [[ $# -ge 1 ]]; then
    INTERFACE=$1
fi

echo \"[*] Iniciando WiFiAutoPwn en la interfaz $INTERFACE...\"
python3 wifi_auto_pwn.py \"$INTERFACE\"
