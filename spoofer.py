#!/usr/bin/env python3

from argparse import ArgumentParser
from ipaddress import ip_address

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send


def add_spoofing_cli_options(parser: (ArgumentParser | None) = None) -> ArgumentParser:
    if parser is None:
        parser = ArgumentParser()
    parser.add_argument(
        "--spoof-source-ip",
        type=ip_address,
        help="changes source IP of the echo-request ICMP packet"
    )
    parser.add_argument(
        "--spoof-destination-ip",
        type=ip_address,
        required=True,
        help="changes source IP of the echo-request ICMP packet"
    )
    return parser


def start_spoof():
    args = add_spoofing_cli_options().parse_args()
    ip_layer = IP()
    if args.spoof_source_ip is not None:
        print(
            f"[*] Spoofer: source IP from {ip_layer.src} to {args.spoof_source_ip}...")
        ip_layer.src = str(args.spoof_source_ip)
    else:
        print(f"[*] Spoofer: source IP {ip_layer.src}")

    print(f"[*] Spoofer: destination IP {args.spoof_destination_ip}...")
    ip_layer.dst = str(args.spoof_destination_ip)
    protocol = ICMP()
    packet = ip_layer / protocol
    send(packet)


if __name__ == "__main__":
    start_spoof()
