ya rien qui marche on recommence et ne modifie rein du code ok #!/usr/bin/env python3


from scapy.all import IP, TCP, sr1, send,UDP,ICMP
from colorama import Fore,init
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import argparse
import socket
import time
import sys
from queue import Queue

open_port=Queue()
close_port=Queue()
filtered_port=Queue()


def is_valid_ip(ip):
    """Vérifie si l'adresse IP est valide (IPv4)."""
    try:
        socket.inet_pton(socket.AF_INET, ip)  # Vérifie si c'est une adresse IPv4 valide.
        return True
    except socket.error:
        return False

def check_ip_reachability(ip):
    """Vérifie si l'IP est accessible via un ping."""
    response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
    if response:
        return True
    else:
        return False
init(autoreset=True)

def scan_port(ip,port_input,funcscan):
    if '-' in port_input:
        try:
            start_port,end_port=map(int,port_input.split('-'))
            if start_port > end_port:
                print("[!] Invalid range: start port is more litle than end port.")
                return
            port_list=range(start_port,end_port+1)
            with ThreadPoolExecutor(max_workers=30) as executor:
                executor.map(lambda port: funcscan(ip, port), port_list)
            while not open_port.empty():
                print(f"[+] Port {Fore.GREEN}{open_port.get()}{Fore.RESET} is open")
        except ValueError:
            print("[!] Invalid port range format.")
    elif ',' in port_input:
        try:
            port_list=[int(port) for port in port_input.split(',')]
            with ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(lambda port: funcscan(ip, port), port_list)
            while not  open_port.empty():
                print(f"[+] Port {Fore.GREEN}{open_port.get()}{Fore.RESET} is open ")

            while not  close_port.empty():
                print(f"[+] Port {Fore.RED}{close_port.get()}{Fore.RESET} is close")
            
            while not  filtered_port.empty():
                print(f"[+] Port {Fore.YELLOW}{filtered_port.get()}{Fore.RESET} is filtered")
        except ValueError:
            print("[!] Invalid port format")
            exit(0)
    else:
        try:
            port_list=port_input

            funcscan(ip, int(port_list))
            while not  open_port.empty():
                print(f"[+] Port {Fore.GREEN}{open_port.get()}{Fore.RESET} is open ")
            while not  close_port.empty():
                print(f"[+] Port {Fore.RED}{close_port.get()}{Fore.RESET} is close")
            while not  filtered_port.empty():
                print(f"[+] Port {Fore.YELLOW}{filtered_port.get()}{Fore.RESET} is filtered")
        except ValueError:
            print("[!] Invalid port format")
            exit(0)



def scan_syn_func(ip, port):
    """Scanne un port en envoyant un paquet SYN et traite la réponse."""
    try:
        # Créer un paquet SYN
        syncscan = IP(dst=ip) / TCP(dport=port, flags="S")
        sendersync = sr1(syncscan, timeout=0.1, verbose=0)

        if sendersync:
            if sendersync.haslayer(TCP) and sendersync.getlayer(TCP).flags == 18:
                sendscap = IP(dst=ip) / TCP(dport=port, flags="R")
                send(sendscap, verbose=0)
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

def scan_tcp_func(ip, port):
    """Scanne un port en envoyant un paquet SYN et traite la réponse."""
    try:
        # Créer un paquet SYN
        tcpscan = IP(dst=ip) / TCP(dport=port, flags="S")
        sendertcp = sr1(tcpscan, timeout=1, verbose=0)

        if sendertcp:
            if sendertcp.haslayer(TCP) and sendertcp.getlayer(TCP).flags == 18:
                sendflags = IP(dst=ip) / TCP(dport=port, flags="A")
                send(sendflags, verbose=0)
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



def scan_udp_func(ip, port):
    """Scanne un port UDP et vérifie l'état en fonction de la réponse ICMP ou de l'absence de réponse."""
    try:
        udpscan = IP(dst=ip) / UDP(dport=port)
        sendudp = sr1(udpscan, timeout=20, verbose=0)  
        
        if sendudp is None:
            print(f"[+] Port {Fore.YELLOW}{port}{Fore.RESET} open or filtered")
        elif sendudp.haslayer(ICMP):
            if sendudp.getlayer(ICMP).type == 3 and sendudp.getlayer(ICMP).code == 3:
                print(f"[+] Port {Fore.RED}{port}{Fore.RESET} is closed")
        else:
            print(f"[+] Port {Fore.GREEN}{port}{Fore.RESET} is open")
    except Exception as e:
        print(f"[!] Error scanning UDP port {port}: {e}")
    time.sleep(2)


def osdetection(ip, port):
    """Détecte l'OS de l'hôte en fonction de la réponse SYN-ACK."""
    try:
        syncscanne = IP(dst=ip) / TCP(dport=port, flags="S")
        sendersync = sr1(syncscanne, timeout=1, verbose=0)
        if sendersync:
            if sendersync.haslayer(TCP):
                ttl = sendersync.ttl
                wind = sendersync[TCP].window
                print(f"[+] TTL: {ttl}, TCP Window: {wind}")
                if ttl >= 64 and ttl <= 128:
                    if wind == 65535:
                        print("[+] OS : Windows")
                    else:
                        print("[+] OS : Linux")
        else:
            print("[+] OS : Not found")
    except socket.gaierror as e:
        print(f"[!] Invalid IP address or  host down: {e}")
    except Exception as excep:
        print(f"An error occurred it is imposible to detecting the OS: {excep}")

def scan_ports_syn(ip,port_input):
    """Scanne plusieurs ports en parallèle avec une limitation de 10 threads simultanés."""
    current_datetime = datetime.now()
    print(f"Starting SYN scanning at: {current_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scan report for {ip}\n")
    scan_port(ip,port_input,scan_syn_func)

               
def scan_ports_tcp(ip, port_input):
    current_datetime = datetime.now()
    print(f"Starting TCP scanning at: {current_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scan report for {ip}\n")
    scan_port(ip,port_input,scan_tcp_func)

def scan_port_udp(ip,port_list):
    current_datetime = datetime.now()
    print(f"Starting UDP scanning at: {current_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scan report for {ip}")
    print()
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(lambda port:scan_udp_func(ip,int(port)),port_list)


def main():
    parser = argparse.ArgumentParser(description="Port scanner script")
    parser.add_argument('-t', '--target', dest='ip_target', type=str, required=True, help="Specify the target IP address")
    parser.add_argument('-p', '--port', dest='port_list', type=str, required=True, help="Specify ports separated by commas")
    parser.add_argument("-S", "--syn", action="store_true", dest="scanSyn", help="Scan SYN")
    parser.add_argument("-T", "--tcp", action="store_true", dest="scanTcp", help="Scan TCP")
    parser.add_argument("-U", "--udp", action="store_true", dest="scanUdp", help="Scan UDP")
    parser.add_argument("-o", "--osdetection", action="store_true", dest="os_detection", help="Execute OS Detection")

    args = parser.parse_args()

    ip_addr = args.ip_target  # Adresse IP cible
    

    # Vérifier la validité de l'IP
    if not is_valid_ip(ip_addr):
        print(f"[!] Invalid IP address: {ip_addr}")
        return

    # Vérifier si l'IP est joignable
    if not check_ip_reachability(ip_addr):
       print(f"[!] The IP address {ip_addr} is not reachable.")
       return

    startt = time.time()

    # Lancer le scan
    if args.scanSyn:
        scan_ports_syn(ip_addr, args.port_list)
    elif args.scanTcp:
        scan_ports_tcp(ip_addr, args.port_list)
    elif args.scanUdp:
        scan_port_udp(ip_addr,args.port_list)
    else:
        print("\n Please choose the scanning mode")

    # Détection de l'OS
    if args.os_detection  and ',' in args.port_list:
        osdetection(ip_addr, int(args.port_list.split(',')[0]))
    elif '-' in args.port_list and args.os_detection:
        osdetection(ip_addr, int(args.port_list.split('-')[0]))
    elif args.os_detection and args.port_list.isdigit():
        osdetection(ip_addr, int(args.port_list))


    endt = time.time()

    scan_duration = endt - startt
    print(f"\n{Fore.GREEN}Scan completed in {Fore.YELLOW}{scan_duration:.2f}{Fore.GREEN} seconds{Fore.RESET}")

if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print(f"{Fore.RED} \nTry running this script as administrator. {Fore.RESET}")
