#!/usr/bin/env python3
from scapy.all import IP, TCP, sr, send
from colorama import Fore
from datetime import datetime
from core.scan_core import scan_port
from utils.queues import open_port, close_port, filtered_port
import socket

def scan_syn_func(ip, port):
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        ans, unans = sr(pkt, timeout=1, verbose=0)

        if ans:
            response = ans[0][1]
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=0)  # Envoie RST pour fermer proprement
                open_port.put(port)
            else:
                close_port.put(port)
        else:
            filtered_port.put(port)

    except PermissionError as Permission:
        print(f"Permission error: {Permission}. Try running this script as administrator.")
    except socket.error as socket_error:
        print(f"Network (socket) error: {socket_error}. Check network connectivity.")
    except Exception as excep:
        print(f"An error occurred while sending the packet: {excep}")

def scan_ports_syn(ip, port_input):
    current_datetime = datetime.now()
    print(f"Starting SYN scanning at: {current_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scan report for {ip}\n")
    scan_port(ip, port_input, scan_syn_func)
