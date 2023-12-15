# Required Imports
from flask import Flask, render_template, send_file, after_this_request
from PyQt5.QtCore import *
from PyQt5.QtWebEngineWidgets import *
from PyQt5.QtWidgets import QApplication
from threading import Timer, Thread, Lock
from scapy.all import Ether, ARP, srp, sniff
import sys
import os
import time

# Initializing Flask Application 
app = Flask(__name__)

# Creating Required Routings
@app.route("/", methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route("/traffic", methods=['GET', 'POST'])
def traffic():
    return render_template('traffic.html', packets=packet_list)

@app.route("/menu", methods=['GET', 'POST'])
def menu():
    return render_template('menu.html')

# Utility route to send the image from server to client 
@app.route("/menu/<name>", methods=['GET'])
def send_menu(name):
    filepath = os.path.join(os.cwd(), "images", name)
    if os.path.isfile(filepath):
        return send_file(filepath)

sent_list = []
LOCK = Lock()

# For sending packets from backend to frontend GUI
@app.route("/get_packets", methods=['GET'])
def send_packet():
    @after_this_request
    def add_header(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    # Using locks for updating packet_list one at a time
    if LOCK.acquire(False):
        global sent_list
        global packet_list
        global under_attack
        global fake_mac
        global real_mac
        new_packets = set(packet_list) - set(sent_list)
        sent_list = packet_list.copy()
        LOCK.release()
        # returning JSON with relevant information
        return {"packets":list(new_packets), 
                "under_attack": under_attack,
                "real_mac": real_mac,
                "fake_mac": fake_mac}
    else:
        return {"packets": [], "under_attack": under_attack, 
        "real_mac":real_mac, "fake_mac": fake_mac}


# Function to Setup QtWebEngine
def gui(url):
    qt_app = QApplication(sys.argv)
    web = QWebEngineView()
    web.setWindowTitle("GUI for MITM Detection App")
    web.resize(1000, 900)
    web.setZoomFactor(1.0)
    web.load(QUrl(url))
    web.show()
    sys.exit(qt_app.exec_())

# Network Traffic Capturing
packet_list = []
packets_updated = True
under_attack = False
real_mac = ""
fake_mac = ""

# Returns the MAC address of IP
def get_mac(ip):
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    resp = srp(p, timeout=2, verbose=False)[0]
    return resp[0][1].hwsrc

## Function to disable the network interface Wi-Fi
# def disable():
#     os.system("netsh interface set interface 'Wi-Fi' disabled")
#     pass

# Checks packet if it's safe or malicious
# Main handler function to detect Man-in-the-middle
def is_under_attack(packet):
    global under_attack 
    global real_mac
    global fake_mac
    global packet_list

    if LOCK.acquire(False):
        packet_list.insert(0, packet.summary())
        LOCK.release()
        # Checking if the packet is an ARP packet
        if packet.haslayer(ARP):
            # If it is an ARP response i.e. ARP reply
            if packet[ARP].op == 2:
                try:
                    # Get the real MAC address of the sender
                    real_mac = get_mac(packet[ARP].psrc)
                    # Get the spoofed MAC address from the packet sent to us
                    spoofed_mac = packet[ARP].hwsrc
                    # If they're different, definitely there is an attack
                    if real_mac != spoofed_mac:
                        print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {spoofed_mac.upper()}")
                        under_attack = True
                        real_mac = real_mac.upper(),
                        fake_mac = spoofed_mac.upper()
                        # disable()
                # Unable to find the real mac
                except IndexError:
                    pass
        # time.sleep(1)


def sniffer():
    # Sniffs the packets on interface and checks the status using is_under_attack function
    # Change the interface name as needed
    sniff(iface="WiFi", prn = is_under_attack) 

if __name__ == "__main__":
    try:
        # Starting a sub-thread to open the browser
        Timer(1,lambda: gui("http://127.0.0.1:5000/")).start()
        
        # Another sub-thread for packet sniffing 
        th_sniff = Thread(target=lambda: sniffer())
        th_sniff.setDaemon(True)
        th_sniff.start()
        
        # Running the flask app on main thread 
        app.run(debug = False)

    except KeyboardInterrupt:
        th_sniff.join()
        exit(0)