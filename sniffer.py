#!/usr/bin/env python3

from typing import Callable
from argparse import ArgumentParser
from ipaddress import IPv4Address

from scapy.config import conf
from scapy.sendrecv import sniff
from scapy.layers.l2 import Ether

from filtering import FilterBuilder, Protocol


def add_sniffing_cli_options(parser: (ArgumentParser | None) = None) -> ArgumentParser:
    if parser is None:
        parser = ArgumentParser()
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="outputs packet details instead of summary"
    )
    parser.add_argument(
        "--sniff-interface",
        type=str,
        choices=list(conf.ifaces),
        help="sniffs using interface chosen",
        default=None
    )
    parser.add_argument(
        "--sniff-protocol",
        type=lambda protocol: Protocol[protocol],
        choices=list(Protocol),
        help="filters sniffed packets based on the protocols allowed"
    )
    parser.add_argument(
        "--sniff-source-port",
        type=int,
        choices=range(0, 256),
        metavar="{0-255}",
        help="filters sniffed packets from source port (from 0 to 255)"
    )
    parser.add_argument(
        "--sniff-destination-port",
        type=int,
        choices=range(0, 256),
        metavar="{0-255}",
        help="filters sniffed packets to destination port (from 0 to 255)"
    )
    parser.add_argument(
        "--sniff-source-ip",
        type=IPv4Address,
        help="filters sniffed packets from source IP"
    )
    parser.add_argument(
        "--sniff-destination-ip",
        type=IPv4Address,
        help="filters sniffed packets from destination IP"
    )
    parser.add_argument(
        "--sniff_ip-exclusive",
        action="store_true",
        default=None,
        help="sets IP filter to only from source IP and to destination IP"
    )
    parser.add_argument(
        "--sniff-source-subnet",
        type=int,
        choices=range(0, 33),
        metavar="{0-32}",
        help="filters sniffed packets from source subnet (from 0 to 32)"
    )
    parser.add_argument(
        "--sniff-destination-subnet",
        type=int,
        choices=range(0, 33),
        metavar="{0-32}",
        help="filters sniffed packets to destination subnet (from 0 to 32)"
    )

    return parser


def start_sniff(verbose: bool, sniff_filter: str, sniff_interface: str | None = None, sniff_function: Callable[[Ether], str | None] | None = None) -> None:
    print(
        f"\n[*] Sniffing with filter \"{sniff_filter if sniff_filter else None}\"...\n")

    if sniff_function is None:
        def sniff_function(packet):
            return packet.show() if args.verbose else packet.summary()

    sniff(
        iface=sniff_interface,
        filter=sniff_filter,
        prn=sniff_function
    )


if __name__ == "__main__":
    args = add_sniffing_cli_options().parse_args()
    sniff_filter = FilterBuilder() \
        .set_protocol(args.sniff_protocol) \
        .set_source_ip(args.sniff_source_ip) \
        .set_destination_ip(args.sniff_destination_ip) \
        .set_source_subnet(args.sniff_source_subnet) \
        .set_destination_subnet(args.sniff_destination_subnet) \
        .set_source_port(args.sniff_source_port) \
        .set_destination_port(args.sniff_destination_port) \
        .set_ip_exclusive(args.sniff_ip_exclusive) \
        .build()

    start_sniff(
        verbose=args.verbose,
        sniff_filter=sniff_filter,
        sniff_interface=args.sniff_interface
    )
