#!/usr/bin/env python3
from scapy.all import IP, TCP, sr, send
from colorama import Fore
from datetime import datetime
from core.scan_core import scan_port
from utils.queues import open_port, close_port, filtered_port
import socket


def scan_tcp_func(ip, port):
    try:
        tcpscan = IP(dst=ip) / TCP(dport=port, flags="S")
        answered,unanswered  = sr(tcpscan, timeout=2, verbose=0)

        if answered:
            sent_pkt, recv_pkt = answered[0]
            if recv_pkt.haslayer(TCP) and recv_pkt.getlayer(TCP).flags == 0x12:
                ack_num = recv_pkt.seq + 1
                seq_num = recv_pkt.ack
                ack_packet  = IP(dst=ip) / TCP(dport=port, flags="A", seq=seq_num, ack=ack_num)
                send(ack_packet, verbose=0)
                open_port.put(port)
            else:
                close_port.put(port)
        else:
            filtered_port.put(port)
    except socket.gaierror as e:
        print(f"[!] Invalid IP address or unreachable host: {e}")
    except PermissionError as Permission:
        print(f"{Permission}. Try running this script as administrator.")
    except socket.error as socket_error:
        print(f"Network (socket) error: {socket_error}. Check network connectivity.")
    except Exception as excep:
        print(f"An error occurred while sending the packet: {excep}")


def scan_ports_tcp(ip, port_input):
    current_datetime = datetime.now()
    print(f"Starting TCP scanning at: {current_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scan report for {ip}\n")
    scan_port(ip, port_input, scan_tcp_func)
