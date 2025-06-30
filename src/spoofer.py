from utils import get_our_mac_addr, get_default_gateway_ip, get_mac_addr

class Spoof:
    def __init__(self, victim_ip: str):
        self.__our_mac = get_our_mac_addr()  # Get our MAC
        self.__victim_ip = victim_ip
        self.__victim_mac = get_mac_addr(self.__victim_ip)  # Get MAC of victim
        self.__default_gateway_ip = get_default_gateway_ip()  # Get IP of default gateway
        self.__default_gateway_mac = get_mac_addr(self.__default_gateway_ip)  # Get MAC of default gateway