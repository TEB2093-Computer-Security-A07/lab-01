#!/usr/bin/env python3

from argparse import ArgumentParser
from ipaddress import IPv4Address

from scapy.layers.l2 import Ether
from scapy.config import conf
from scapy.layers.inet import ICMP, IP

from filtering import FilterBuilder, Protocol
from sniffer import add_sniffing_cli_options, start_sniff
from spoofer import start_spoof


def add_sniffing_cli_options(parser: (ArgumentParser | None) = None) -> ArgumentParser:
    if parser is None:
        parser = ArgumentParser()
    parser.add_argument(
        "--sniff-interface",
        type=str,
        choices=list(conf.ifaces),
        help="sniffs using interface chosen",
        default=None
    )
    parser.add_argument(
        "--sniff-source-ip",
        type=IPv4Address,
        help="filters sniffed packets from source IP"
    )
    parser.add_argument(
        "--sniff-source-port",
        type=int,
        choices=range(0, 256),
        metavar="{0-255}",
        help="filters sniffed packets from source port (from 0 to 255)"
    )
    parser.add_argument(
        "--sniff-source-subnet",
        type=int,
        choices=range(0, 33),
        metavar="{0-32}",
        help="filters sniffed packets from source subnet (from 0 to 32)"
    )

    return parser


def set_interface_and_spoof_icmp(interface: str | None) -> None:

    def spoof_icmp(packet: Ether) -> None:
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            origin_src_ip = packet[IP].src
            origin_dst_ip = packet[IP].dst

            print(
                f"[+] Detected ICMP echo-request from {origin_src_ip} to {origin_dst_ip}!")

            packet.show2()

            custom_icmp = ICMP(
                type=0,
                code=0,
                id=packet[ICMP].id,
                seq=packet[ICMP].seq
            )

            custom_icmp.payload = packet[ICMP].payload

            start_spoof(
                spoof_source_ip=origin_dst_ip,
                spoof_destination_ip=origin_src_ip,
                spoof_interface=interface,
                custom_packet=custom_icmp
            )

            print(
                f"[+] Sent spoofed ICMP echo-reply as {origin_dst_ip} to {origin_src_ip} over the interface {interface}!")
    return spoof_icmp


if __name__ == "__main__":
    args = add_sniffing_cli_options().parse_args()

    sniff_filter = FilterBuilder() \
        .set_protocol(Protocol.ICMP) \
        .set_source_ip(args.sniff_source_ip) \
        .set_source_subnet(args.sniff_source_subnet) \
        .set_source_port(args.sniff_source_port) \
        .build()

    start_sniff(
        verbose=False,
        sniff_filter=sniff_filter,
        sniff_interface=args.sniff_interface,
        sniff_function=set_interface_and_spoof_icmp(
            interface=args.sniff_interface
        )
    )
