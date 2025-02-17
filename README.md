# WiFiAutoPwn

WiFiAutoPwn es una herramienta automatizada para realizar auditorías de seguridad en redes WiFi, incluyendo captura de handshakes y ataques de phishing con Wifiphisher.

## ⚡ Instalación

```bash
chmod +x install.sh start.sh
./install.sh
```

## 🚀 Uso

Ejecuta la herramienta con:

```bash
./start.sh [interfaz]
```

Ejemplo:

```bash
./start.sh wlan0
```

## 🔧 Funcionalidades
- Escaneo de redes WiFi.
- Captura de handshakes para ataque por diccionario.
- Ataques de phishing con Wifiphisher.

## 📜 Requisitos
- Python 3
- aircrack-ng
- hcxdumptool
- hashcat
- wifiphisher

## ⚠️ Disclaimer
Esta herramienta debe ser utilizada únicamente con fines educativos y en entornos donde tengas permiso para realizar pruebas de seguridad.
