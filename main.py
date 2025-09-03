#!/usr/bin/env python3
import argparse
import time
from colorama import Fore, init
from utils.utils import is_valid_ip, check_ip_reachability
from scans.scan_syn import scan_ports_syn
from scans.scan_tcp import scan_ports_tcp
from scans.scan_udp import scan_port_udp
from os_detection import osdetection
from math import floor



def main():
    parser = argparse.ArgumentParser(description="Port scanner script")
    parser.add_argument('-t', '--target', dest='ip_target', type=str, required=True, help="Specify the target IP address")
    parser.add_argument('-p', '--port', dest='port_list', type=str, required=True, help="Specify ports separated by commas")
    parser.add_argument("-S", "--syn", action="store_true", dest="scanSyn", help="Scan SYN")
    parser.add_argument("-T", "--tcp", action="store_true", dest="scanTcp", help="Scan TCP")
    parser.add_argument("-U", "--udp", action="store_true", dest="scanUdp", help="Scan UDP")
    parser.add_argument("-o", "--osdetection", action="store_true", dest="os_detection", help="Execute OS Detection")

    args = parser.parse_args()
    ip_addr = args.ip_target

    if not is_valid_ip(ip_addr):
        print(f"[!] Invalid IP address: {ip_addr}")
        return

    if not check_ip_reachability(ip_addr):
        print(f"[!] The IP address {ip_addr} is not reachable.")
        return

    startt = time.time()

    if args.scanSyn:
        scan_ports_syn(ip_addr, args.port_list)
    elif args.scanTcp:
        scan_ports_tcp(ip_addr, args.port_list)
    elif args.scanUdp:
        scan_port_udp(ip_addr, args.port_list)
    else:
        print("\n Please choose the scanning mode")

    if args.os_detection and ',' in args.port_list:
        osdetection(ip_addr, int(args.port_list.split(',')[0]))
    elif '-' in args.port_list and args.os_detection:
        osdetection(ip_addr, int(args.port_list.split('-')[0]))
    elif args.os_detection and args.port_list.isdigit():
        osdetection(ip_addr, int(args.port_list))

    endt = time.time()
    scan_duration = endt - startt
    if scan_duration >= 60:
        scan_duration_min=scan_duration/60
        print(f"\n{Fore.GREEN}Scan completed in {Fore.YELLOW}{floor(scan_duration_min)}{Fore.GREEN}min{Fore.GREEN} {scan_duration%60:.0f} sec {Fore.RESET} ")
    else:
        print(f"\n{Fore.GREEN}Scan completed in {Fore.YELLOW}{scan_duration:.2f}{Fore.GREEN} {Fore.GREEN} seconds{Fore.RESET}")


if __name__ == "__main__":
    try:
        init(autoreset=True)
        main()
    except PermissionError:
        print(f"{Fore.RED} \nTry running this script as administrator. {Fore.RESET}")
