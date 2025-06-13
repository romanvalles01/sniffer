from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict
from colorama import Fore, Style, init
import json
import signal
import sys

init(autoreset=True)

counter = defaultdict(int)
log_data = []
stop_sniffer = False

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "UNKNOWN"

        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"

        color = {
            "TCP": Fore.CYAN,
            "UDP": Fore.GREEN,
            "UNKNOWN": Fore.MAGENTA
        }.get(proto, Fore.WHITE)

        time_now = datetime.now().strftime('%H:%M:%S')
        print(f"{color}[{time_now}] {src} → {dst} ({proto}){Style.RESET_ALL}")

        counter[proto] += 1
        log_data.append({
            "time": time_now,
            "src": src,
            "dst": dst,
            "proto": proto
        })

def stop_handler(_sig, _frame):
    global stop_sniffer
    stop_sniffer = True
    print(Fore.LIGHTRED_EX + "\n Sniffer detenido por el usuario." + Style.RESET_ALL)
    print("\n Resumen de paquetes capturados:")
    for proto, count in counter.items():
        print(f"  {proto}: {count} paquetes")

    with open("log.json", "w") as f:
        json.dump(log_data, f, indent=2)
    print(Fore.LIGHTYELLOW_EX + "\n Log guardado en log.json" + Style.RESET_ALL)
    sys.exit(0)

# Registrar la señal Ctrl+C
signal.signal(signal.SIGINT, stop_handler)

print(Fore.LIGHTBLUE_EX + "Sniffer corriendo. Presioná Ctrl+C para detener." + Style.RESET_ALL)

sniff(prn=packet_callback, store=False, stop_filter=lambda x: stop_sniffer)