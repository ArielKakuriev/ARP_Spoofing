from scapy.all import srp1, Ether, conf, ARP, send

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