#!/usr/bin/env python3

from argparse import ArgumentParser
from ipaddress import ip_address

from scapy.all import *
from scapy.layers.inet import IP, ICMP


def add_traceroute_cli_options(parser: (ArgumentParser | None) = None) -> ArgumentParser:
    if parser is None:
        parser = ArgumentParser()
    parser.add_argument(
        "--traceroute-destination-ip",
        type=ip_address,
        help="source IP of the ICMP packet",
        required=True
    )
    parser.add_argument(
        "--traceroute-start-ttl",
        type=int,
        help="start of time-to-live (TTL) for ICMP packet",
        default=1
    )
    parser.add_argument(
        "--traceroute-end-ttl",
        type=int,
        help="end of time-to-live (TTL) for ICMP packet",
        default=10
    )
    return parser


def start_traceroute():
    args = add_traceroute_cli_options().parse_args()

    ip_layer = IP(dst=str(args.traceroute_destination_ip))
    protocol = ICMP()

    print(f"[+] Route set from {ip_layer.src} to {ip_layer.dst}!")

    for current_ttl in range(args.traceroute_start_ttl, args.traceroute_end_ttl + 1):
        print(f"[*] Tracing route with ICMP of TTL {current_ttl}...")
        ip_layer.ttl = current_ttl
        packet = ip_layer / protocol
        response = sr1(packet, verbose=0)

        if response is None:
            print(f"\t[-] No response received.")
            continue

        src_ip = response.src

        icmp_layer = response.getlayer(ICMP)

        if icmp_layer.type == 0:
            # ICMP Echo Reply: Destination reached
            print(f"\t[+] Destination reached to {src_ip}!")
            break
        elif icmp_layer.type == 11 and icmp_layer.code == 0:
            print(f"\t[-] TTL reached at {src_ip}.")
        elif icmp_layer.type == 3:
            print("\t[-] Destination unreachable.")
            break
        else:
            print("\t[-] Something happened and I do not know why :(")


if __name__ == "__main__":
    start_traceroute()
