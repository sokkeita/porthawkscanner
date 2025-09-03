#!/usr/bin/env python3
import socket
from scapy.all import IP, ICMP, sr1


def is_valid_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False


def check_ip_reachability(ip):
    response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
    return bool(response)
