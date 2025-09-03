#!/usr/bin/env python3
from scapy.all import IP, TCP, sr1
import socket


def osdetection(ip, port):
    try:
        syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
 # Very basic OS fingerprinting
            ttl = response[IP].ttl
            window_size = response[TCP].window
            print(f"\n[+] TTL: {ttl}, TCP Window: {window_size}")
            if ttl <= 64:
                if window_size == 5840:
                    print("[+] Possible OS: Linux")
                else:
                    print("[+] Possible OS: Unix-like")
            elif ttl <= 128:
                if window_size == 65535:
                    print("[+] Possible OS: Windows")
                else:
                    print("[+] Possible OS: Windows or other")
            elif ttl > 128:
                print("[+] Possible OS: Cisco device or unknown high-TTL system")
        else:
            print("[-] No response received (host may be down or filtered)")
    except socket.gaierror as e:
        print(f"[!] Invalid IP address or  host down: {e}")
    except Exception as excep:
        print(f"An error occurred it is impossible to detecting the OS: {excep}")
