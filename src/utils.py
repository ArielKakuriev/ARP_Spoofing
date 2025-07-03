import random
from ipaddress import IPv4Network
from netifaces import gateways, AF_INET, ifaddresses
from scapy.all import srp1, Ether, conf, ARP, send, srp

DEFAULT_ROUTE = "0.0.0.0"
INDEX_OF_IP_ROUTE = 2
BROADCAST_MAC = "ff:ff:ff:ff:ff"
DEFAULT_SEND_COUNT = 1

"""
This function gives our mac address
"""
def get_our_mac_addr() -> str:
    return Ether().src

"""
This function gives the default gateway IP
"""
def get_default_gateway_ip() -> str:
    # Get the IP of default gateway from Scapy's routing table
    return conf.route.route(DEFAULT_ROUTE)[INDEX_OF_IP_ROUTE]

"""
This function gives the MAC address of some IP
Input: The IP to find his MAC
Output: The MAC of the IP 
"""
def get_mac_addr(ip: str) -> str:
    msg = Ether(dst=BROADCAST_MAC) / ARP(pdst=ip)  # ARP packet to get the MAC of the IP
    res = srp1(msg, verbose=0)
    return res[ARP].hwsrc  # MAC addr of IP

"""
This function send an ARP packet
Input: The opcode of ARP packet. The MAC & IP of the src. The MAC & IP of the dst. How much times to send the packet(default: 1)
Output: None
"""
def send_arp_packet(opcode: int, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str, times_to_send: int = DEFAULT_SEND_COUNT) -> None:
    send(ARP(op=opcode, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip), count=times_to_send)  # Send an ARP packet

"""
This function generate a valid random MAC address
Input: None
Output: The random MAC address
"""
def generate_fake_mac() -> str:
    first_byte = random.randint(0x00, 0xFF)  # Generate the first byte of the MAC
    first_byte = (first_byte & 0b11111100) | 0b00000010  # Make first byte of the MAC to be valid for spoofing
    mac_bytes = [first_byte] + [random.randint(0x00, 0xFF) for _ in range(5)]  # Create a list of all the bytes in the MAC
    return ':'.join(f'{b:02x}' for b in mac_bytes)  # Formatting it to MAC

"""
This function checks if a MAC address is in our LAN
Input: The MAC to check if exist in LAN
Output: If MAC address is in the LAN or not
"""
def is_mac_in_lan(target_mac: str) -> bool:
    ip_range = ""  # TODO: function of get IP range
    msg = Ether(dst=BROADCAST_MAC) / ARP(pdst=ip_range)
    answered_list, unanswered_list = srp(msg, timeout=1, verbose=False)
    for sent, received in answered_list:  # Search for the mac address
        if received.hwsrc == target_mac:  # If MAC is in LAN
            return True
    return False

"""
This function gives our IP range in LAN in cidr format
Input: None
Output: The IP range of LAN
"""
def get_lan_ip_range_cidr() -> str:
    network_iface = gateways()['default'][AF_INET][1]  # Get the name of the network interface
    addr_info = ifaddresses(network_iface)[AF_INET][0]  # Get an info about the address configuration in our network interface
    ip = addr_info['addr']  # Take the IP
    netmask = addr_info['netmask']  # Get the subnet mask
    cidr = IPv4Network(f"{ip}/{netmask}", strict=False).prefixlen  # Get the CIDR notation
    return f"{ip}/{cidr}"