#!/usr/bin/env python3

from argparse import ArgumentParser
from ipaddress import ip_address, IPv4Address

from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.sendrecv import send, sendp
from scapy.plist import PacketList


def add_spoofing_cli_options(parser: (ArgumentParser | None) = None) -> ArgumentParser:
    if parser is None:
        parser = ArgumentParser()
    parser.add_argument(
        "--spoof-source-ip",
        type=IPv4Address,
        help="changes source IP of the echo-request ICMP packet"
    )
    parser.add_argument(
        "--spoof-destination-ip",
        type=IPv4Address,
        required=True,
        help="changes source IP of the echo-request ICMP packet"
    )
    return parser


def start_spoof(spoof_source_ip: IPv4Address, spoof_destination_ip: IPv4Address, custom_ether: Ether | None = None, custom_packet: Packet | None = None, spoof_interface: str | None = None) -> PacketList | None:
    ip_layer = IP()
    if spoof_source_ip is not None:
        print(
            f"[*] Spoofer: source IP from {ip_layer.src} to {spoof_source_ip}...")
        ip_layer.src = str(spoof_source_ip)
    else:
        print(f"[*] Spoofer: source IP {ip_layer.src}")

    print(f"[*] Spoofer: destination IP {spoof_destination_ip}...")
    ip_layer.dst = str(spoof_destination_ip)
    protocol = custom_packet if custom_packet else ICMP()

    if custom_ether is not None:
        packet = custom_ether / ip_layer / protocol
    else:
        packet = ip_layer / protocol

    print(f"[+] Spoofed packet built!")
    packet.show2()

    return sendp(packet, iface=spoof_interface) if custom_ether is not None else send(packet)


if __name__ == "__main__":
    args = add_spoofing_cli_options().parse_args()
    start_spoof(args.spoof_source_ip, args.spoof_destination_ip)
