from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        if protocol == 1:
            proto_name = "ICMP"
        elif protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        else:
            proto_name = str(protocol)
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {proto_name}")
        if TCP in packet or UDP in packet:
            payload = packet[TCP].payload if TCP in packet else packet[UDP].payload
            print(f"Payload: {payload}")
        elif ICMP in packet:
            print(f"ICMP Type: {packet[ICMP].type}")
print("Starting packet capture. Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)