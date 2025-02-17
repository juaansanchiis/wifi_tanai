#!/bin/bash
# Script de arranque para WiFiAutoPwn

INTERFACE="wlan0"

if [[ $1 ]]; then
    INTERFACE=$1
fi

echo "[*] Iniciando WiFiAutoPwn en la interfaz $INTERFACE..."
python3 wifi_auto_pwn.py $INTERFACE
