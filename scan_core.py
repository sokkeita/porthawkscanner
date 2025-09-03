#!/usr/bin/env python3
from queues import open_port, close_port, filtered_port
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore


def scan_port(ip, port_input, funcscan):
    if '-' in port_input:
        try:
            start_port, end_port = map(int, port_input.split('-'))
            if start_port > end_port:
                print("[!] Invalid range: start port is more litle than end port.")
                return
            port_list = range(start_port, end_port + 1)
            with ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(lambda port: funcscan(ip, port), port_list)
            while not open_port.empty():
                print(f"[+] Port {Fore.GREEN}{open_port.get()}{Fore.RESET} is open")
        except ValueError:
            print("[!] Invalid port range format.")

    elif ',' in port_input:
        try:
            port_list = [int(port) for port in port_input.split(',')]
            with ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(lambda port: funcscan(ip, port), port_list)
            #print("{:<20} {:<20} {:<20}".format("Ports", "Status", "Services"))
            print("{:<20} {:<20} ".format("Ports", "Status",))
            while not open_port.empty():
                open_port_display=open_port.get()
                #print(f"[+] Port {Fore.RED}{close_port.get()}{Fore.RESET} is close")
                print("{:<20} {:<20} {:<20}".format(open_port_display, f"{Fore.GREEN}open{Fore.RESET}", " "))

            while not close_port.empty():
                #print(f"[+] Port {Fore.RED}{close_port.get()}{Fore.RESET} is close")
                closed_port_display=close_port.get()
                print("{:<20} {:<20} {:<20}".format(closed_port_display, f"{Fore.RED}closed{Fore.RESET}", " "))


            while not filtered_port.empty():
                print(f"[+] Port {Fore.YELLOW}{filtered_port.get()}{Fore.RESET} is filtered")
        except ValueError:
            print("[!] Invalid port format")
            exit(0)

    else:
        try:
            port_list = port_input

            funcscan(ip, int(port_list))
            while not open_port.empty():
                print(f"[+] Port {Fore.GREEN}{open_port.get()}{Fore.RESET} is open ")
            while not close_port.empty():
                print(f"[+] Port {Fore.RED}{close_port.get()}{Fore.RESET} is close")
            while not filtered_port.empty():
                print(f"[+] Port {Fore.YELLOW}{filtered_port.get()}{Fore.RESET} is filtered")
        except ValueError:
            print("[!] Invalid port format")
            exit(0)