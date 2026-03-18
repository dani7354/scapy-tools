#!/usr/bin/env python3

import dataclasses
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
    type: str
    src_ip: str
    dst_ip: str
    domains: list[str] = dataclasses.field(default_factory=list)
    resolved_ips: list[str] = dataclasses.field(default_factory=list)


def _try_parse_response(dns_data: Packet) -> list[str]:
    ips = []
    a = dns_data.an
    while a and hasattr(a, "rdata"):
        ips.append(a.rdata)
        a = a.payload

    return ips


def _try_parse_request(dns_data: Packet) -> tuple[list[str], list[str]]:
    domains = []
    qtypes = []
    q = dns_data.qd
    while q and hasattr(q, "qname"):
        domains.append(q.qname.decode().rstrip(".") if isinstance(q.qname, bytes) else q.qname.rstrip("."))
        qtypes.append(q.qtype)
        q = q.payload

    return qtypes, domains


def list_distinct_domain_names(lookups: list[DNSLookup]) -> set[str]:
    return set(domain for lookup in lookups for domain in lookup.domains)


def get_resolved_ips_by_domain(lookups: list[DNSLookup]) -> dict[str, set[str]]:
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
        ip_layer = p.getlayer(IP)
        src = ""
        dst = ""
        if ip_layer:
            src = ip_layer.src
            dst = ip_layer.dst
            if not src or not dst:
                print("No source or destination IP, skipping...")
                continue

        if not p.haslayer(DNS) or "an" not in dir(p.getlayer(DNS)):
            continue

        dns_data = p.getlayer(DNS)
        if not (request := _try_parse_request(dns_data)):
            print("No domains present in request, skipping...")
            continue

        resolved_ips = _try_parse_response(dns_data)
        qtypes, domains = request
        lookups.append(DNSLookup(
            type=_qtypes[qtypes[0]],
            src_ip=src,
            dst_ip=dst,
            domains=domains,
            resolved_ips=resolved_ips))

    print(len(lookups))
    for l in lookups:
        print(l)

    unique_lookups = list_distinct_domain_names(lookups)
    resolved_ips_by_domain = get_resolved_ips_by_domain(lookups)
    for ri in resolved_ips_by_domain:
        print(f"{ri}: {resolved_ips_by_domain[ri]}")



if __name__ == "__main__":
    main()


