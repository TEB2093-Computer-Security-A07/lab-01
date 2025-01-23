from ipaddress import IPv4Address, IPv6Address
from typing import Self
from enum import Enum


class Protocol(Enum):
    ETHER = "ether"
    IP = "ip"
    IP6 = "ip6"
    ICMP = "icmp"
    TCP = "tcp"
    UDP = "udp"
    ARP = "arp"
    RARP = "rarp"
    HTTP = "tcp port 80"
    HTTPS = "tcp port 443"
    DNS = "port 53"
    FTP = "tcp port 21 or tcp port 20"
    SSH = "tcp port 22"
    TELNET = "tcp port 23"

    def __str__(self) -> str:
        return self.name


class FilterBuilder:
    def __init__(self):
        self._protocol = None
        self._src_ip = None
        self._dst_ip = None
        self._src_port = None
        self._dst_port = None
        self._src_subnet = None
        self._dst_subnet = None
        self._ip_exclusive = None

    def set_protocol(self, protocol: Protocol | None) -> Self:
        if protocol and protocol not in (Protocol.TCP, Protocol.UDP) and (self._src_port is not None or self._dst_port is not None):
            raise ValueError(
                "can't set protocol other than TCP or UDP if port(s) is/are set")
        self._protocol = protocol
        return self

    def set_source_ip(self, source_ip: IPv4Address | IPv6Address | None) -> Self:
        self._src_ip = source_ip
        return self

    def set_destination_ip(self, destination_ip: IPv4Address | IPv6Address | None) -> Self:
        self._dst_ip = destination_ip
        return self

    def set_source_port(self, source_port: int | None) -> Self:
        if source_port is not None:
            if self._protocol not in (Protocol.TCP, Protocol.UDP):
                raise ValueError(
                    "can't set source port if protocol set to other than TCP or UDP")
            if not 0 <= source_port <= 255:
                raise ValueError(
                    "source port has to be from 0 to 255 (inclusive)")
        self._src_port = source_port
        return self

    def set_destination_port(self, destination_port: int | None) -> Self:
        if destination_port is not None:
            if self._protocol not in (Protocol.TCP, Protocol.UDP):
                raise ValueError(
                    "can't set destination port if protocol set to other than TCP or UDP")
            if not 0 <= destination_port <= 255:
                raise ValueError(
                    "destination port has to be from 0 to 255 (inclusive)")
        self._dst_port = destination_port
        return self

    def set_source_subnet(self, source_subnet: int | None) -> Self:
        if source_subnet is not None:
            if self._src_ip is None:
                raise ValueError(
                    "can't set source subnet if source IP is not set")
            if not 0 <= source_subnet <= 32:
                raise ValueError(
                    "destination subnet has to be from 0 to 32 (inclusive)")
        self._src_subnet = source_subnet
        return self

    def set_destination_subnet(self, destination_subnet: int | None) -> Self:
        if destination_subnet is not None:
            if self._src_ip is None:
                raise ValueError(
                    "can't set destination subnet if destination IP is not set")
            if not 0 <= destination_subnet <= 32:
                raise ValueError(
                    "destination subnet has to be from 0 to 32 (inclusive)")
        self._dst_subnet = destination_subnet
        return self

    def set_ip_exclusive(self, ip_exclusive: bool | None) -> Self:
        if ip_exclusive and self._src_ip is None and self._dst_ip is None:
            raise ValueError(
                "IP exclusive can only be set if source and destination IPs are set")
        self._ip_exclusive = ip_exclusive
        return self

    def build(self) -> str | None:
        filters: list[str] = []

        # add protocol to filter
        if self._protocol is not None:
            filters.append(str(self._protocol.value))

        if len(filters) == 1 and len(filters[0].split(' ')) > 1:
            filters.append("and")

        # add src ip, subnet and port
        if self._src_ip is not None:
            if self._src_subnet is not None:
                filters.append(f"src net {self._src_ip}/{self._src_subnet}")
            else:
                filters.append(f"src host {self._src_ip}")

        if self._src_port is not None:
            filters.append(f"and src port {self._src_port}")

        # combine src to dst
        if self._ip_exclusive:
            filters.append("and")
        elif self._dst_ip is not None:
            filters.append("or")

        # add dst ip, subnet and port
        if self._dst_ip is not None:
            if self._dst_subnet is not None:
                filters.append(f"dst net {self._dst_ip}/{self._dst_subnet}")
            else:
                filters.append(f"dst host {self._dst_ip}")

        if self._dst_port is not None:
            filters.append(f"and dst port {self._dst_port}")

        if len(filters) == 0:
            return ""
        return " ".join(filters)
