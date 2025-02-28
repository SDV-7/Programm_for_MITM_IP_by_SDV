#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.http import HTTPRequest
import argparse

def sniff_http(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        print(f"\n[!] The request for: {url}")
        if packet.haslayer(Raw):
            data = packet[Raw].load.decode(errors="ignore")
            print(f"[+] All data: {data}")  # Выводим ВСЕ данные

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, help="Network interfece (eth0)")
    args = parser.parse_args()
    print("[+] Sniffing HTTP traffic... (Ctrl+C for stop)")
    sniff(iface=args.interface, store=False, prn=sniff_http, filter="tcp port 80")
