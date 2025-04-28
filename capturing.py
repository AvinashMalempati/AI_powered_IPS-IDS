from scapy.all import sniff, wrpcap

# File path to save the captured packets
pcap_file = "/Users/avinash/Documents/capture.pcap"

# Define the network interface for sniffing
network_interface = "en0"  # Change this if you're using another interface

# Define the number of packets to capture
num_packets = 1000


# Function to handle each captured packet (you can extend this if needed)
def packet_handler(packet):
    print(f"Captured Packet: {packet.summary()}")


# Sniff packets on the specified interface
print(f"Capturing {num_packets} packets on the interface '{network_interface}'...")
packets = sniff(iface=network_interface, count=num_packets, prn=packet_handler)

# Save the captured packets to a .pcap file
wrpcap(pcap_file, packets)
print(f"\nPackets saved to: {pcap_file}")
