#!/usr/bin/env python3
from scapy.all import IP, UDP, ICMP, sr1
from colorama import Fore
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import time
from core.scan_core import scan_port
from utils.queues import open_port, close_port, filtered_port

def scan_udp_func(ip, port):
    try:
        udpscan = IP(dst=ip) / UDP(dport=port)
        sendudp = sr1(udpscan, timeout=3, verbose=0)

        if sendudp is None:
            filtered_port.put(port)  # Pas de réponse => open|filtered
        elif sendudp.haslayer(ICMP):
            if sendudp.getlayer(ICMP).type == 3 and sendudp.getlayer(ICMP).code == 3:
                close_port.put(port)
            else:
                filtered_port.put(port)  # ICMP mais autre type/code
        else:
            open_port.put(port)
    except Exception as e:
        print(f"[!] Error scanning UDP port {port}: {e}")


def scan_port_udp(ip, port_input):
    current_datetime = datetime.now()
    print(f"Starting UDP scanning at: {current_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scan report for {ip}\n")
    scan_port(ip, port_input, scan_udp_func)
