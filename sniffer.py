import socket
import struct
import binascii

# Function to format MAC address in a human-readable way
def mac_format(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

# Function to format IP address in a human-readable way
def ip_format(addr):
    return '.'.join(map(str, addr))

# Create a raw socket that will listen for all incoming traffic
# AF_PACKET is used for low-level packet access, and SOCK_RAW allows us to capture raw packets
sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

print("Listening for packets...")

# Main loop to continuously capture and process packets
while True:
    # Receive raw packet data (65565 is the max packet size)
    raw_data, addr = sniffer_socket.recvfrom(65565)
    
    # Ethernet frame is the first layer of the packet (14 bytes header)
    ethernet_header = raw_data[0:14]
    
    # Unpack the Ethernet frame (destination MAC, source MAC, protocol type)
    dest_mac, src_mac, eth_proto = struct.unpack('!6s6sH', ethernet_header)
    
    # Convert MAC addresses and protocol type to human-readable formats
    dest_mac = mac_format(dest_mac)
    src_mac = mac_format(src_mac)
    eth_proto = socket.htons(eth_proto)

    print(f"\nEthernet Frame:")
    print(f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

    # Check if the packet is an IP packet (eth_proto == 8 means it's an IP packet)
    if eth_proto == 8:  # IPv4 packet
        # Extract IP header from the packet (20 bytes)
        ip_header = raw_data[14:34]
        
        # Unpack the IP header
        ip_data = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # Extract various fields from the IP header
        version_header_length = ip_data[0]
        ttl = ip_data[5]
        proto = ip_data[6]  # Protocol (e.g., 6 = TCP, 17 = UDP, 1 = ICMP)
        src_ip = ip_format(ip_data[8])
        dest_ip = ip_format(ip_data[9])
        
        print(f"IP Packet:")
        print(f"Source IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {proto}, TTL: {ttl}")
        
        # Check if the protocol is ICMP (1)
        if proto == 1:  # ICMP protocol
            # ICMP header follows the IP header (8 bytes long)
            icmp_header = raw_data[34:42]
            icmp_type, code, checksum = struct.unpack('!BBH', icmp_header[:4])
            
            # Check if it's an Echo Request (ping) or Echo Reply
            if icmp_type == 8:
                print(f"ICMP Packet: Ping Request (Echo Request) from {src_ip} to {dest_ip}")
            elif icmp_type == 0:
                print(f"ICMP Packet: Ping Reply (Echo Reply) from {src_ip} to {dest_ip}")
