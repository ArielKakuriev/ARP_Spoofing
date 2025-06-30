from scapy.all import srp1, Ether, conf, ARP

DEFAULT_ROUTE = "0.0.0.0"
INDEX_OF_IP_ROUTE = 2
BROADCAST_MAC = "ff:ff:ff:ff:ff"

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