# Network Traffic Capturing
# Code has been inspired by https://www.thepythoncode.com/article/detecting-arp-spoof-attacks-using-scapy 

import socket
from scapy.all import Ether, ICMP,UDP, IP, raw, DNS, ARP, srp, sniff, conf, wrpcap
from pprint import pprint 

# Returns the MAC address of ip
def get_mac(ip):
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc

def process(packet):
    # if the packet is an ARP packet
    if packet.haslayer(ARP):
        # if it is an ARP response (ARP reply)
        if packet[ARP].op == 2:
            try:
                # get the real MAC address of the sender
                real_mac = get_mac(packet[ARP].psrc)
                # get the MAC address from the packet sent to us
                response_mac = packet[ARP].hwsrc
                # if they're different, definetely there is an attack
                if real_mac != response_mac:
                    print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
            except IndexError:
                # unable to find the real mac
                # may be a fake IP or firewall is blocking packets
                pass

def callback(packet):
    try:
        print("SRC: ", socket.gethostbyaddr(packet[IP].src)[0])
        print("DST: ", socket.gethostbyaddr(packet[IP].dst)[0])
    except:
        pass
    print(packet.summary())

if __name__ == "__main__":
    packet_filter = " and ".join([
    "ip",
    "tcp",
     ])

    sniff(iface= "Wi-Fi", filter="ip", prn = callback, count = 100)