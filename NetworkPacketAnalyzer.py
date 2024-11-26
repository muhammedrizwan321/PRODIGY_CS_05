from scapy.all import *
from scapy.config import conf

# Force Layer 3 socket usage
conf.l3socket = conf.L3socket

# Function to handle packet capture
def packet_callback(packet):
    # Extracting relevant details from the packet
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet.proto
        payload = packet.payload if packet.payload else None
        
        # Display packet information
        print(f"Source IP: {source_ip} -> Destination IP: {destination_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload Data: {payload}")
        print("-" * 50)

# Start sniffing network packets
def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # Start the packet sniffer
    start_sniffing()