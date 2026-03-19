#!/usr/bin/env python3

import dataclasses
from collections import Counter
from pathlib import Path
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP


_qtypes = {
    0x01: "A",
    0x02: "NS",
    0x05: "CNAME",
    0x0C: "PTR",
    0x0F: "MX",
}


@dataclasses.dataclass(frozen=True, eq=True)
class DNSLookup:
    transaction_id: int
    client_ip: str
    server_ip: str
    qtypes: list[str]
    domains: list[str] = dataclasses.field(default_factory=list)
    resolved_ips: list[str] = dataclasses.field(default_factory=list)


def _try_parse_ips(data: Packet) -> tuple[str, str] | None:
    server_ip, client_ip = None, None
    if ip_layer := data.getlayer(IP):
        server_ip = ip_layer.src
        client_ip = ip_layer.dst
        if not server_ip or not client_ip:
            return None

    return server_ip, client_ip


def _try_parse_response(dns_data: Packet) -> tuple[list[str], list[str]]:
    ips, types = [], set()
    a = dns_data.an
    if a and hasattr(a, "rdata"):
        for r in a:
            ips.append(r.rdata)
            types.add(_qtypes[r.type])

    return ips, list(types)


def _try_parse_request(dns_data: Packet) -> tuple[list[str], list[str]]:
    domains, qtypes = [], []
    q = dns_data.qd
    while q and hasattr(q, "qname"):
        domains.append(q.qname.decode().rstrip(".") if isinstance(q.qname, bytes) else q.qname.rstrip("."))
        qtypes.append(q.qtype)
        q = q.payload

    return qtypes, domains


def _list_distinct_domain_names(lookups: list[DNSLookup]) -> set[str]:
    return set(domain for lookup in lookups for domain in lookup.domains)


def _list_resolved_ips_by_domain(lookups: list[DNSLookup]) -> dict[str, set[str]]:
    resolved_ips_by_domain = defaultdict(set)
    for l in lookups:
        for d in l.domains:
            resolved_ips_by_domain[d].update(l.resolved_ips)

    return resolved_ips_by_domain



def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    file_path = Path(sys.argv[1])
    if not file_path.is_file():
        print(f"{file_path} not found!")
        sys.exit(1)

    lookups = []
    for p in rdpcap(str(file_path)):
        server_ip, client_ip = _try_parse_ips(p)

        if not p.haslayer(DNS) or not server_ip or not client_ip:
            continue

        dns_data = p.getlayer(DNS)
        is_response = True if dns_data.qr else False
        if not is_response:
            continue

        if not (request := _try_parse_request(dns_data)):
            print("No domains present in request, skipping...")
            continue

        transaction_id = dns_data.id
        resolved_ips, response_types = _try_parse_response(dns_data)
        qtypes, domains = request
        lookups.append(DNSLookup(
            transaction_id= transaction_id,
            client_ip=client_ip,
            server_ip=server_ip,
            qtypes=response_types,
            domains=domains,
            resolved_ips=resolved_ips))

    for l in lookups:
        print(l)

    resolved_ips_by_domain = _list_resolved_ips_by_domain(lookups)
    for ri in resolved_ips_by_domain:
        print(f"{ri}: {resolved_ips_by_domain[ri]}")


if __name__ == "__main__":
    main()


