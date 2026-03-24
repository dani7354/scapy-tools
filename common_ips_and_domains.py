#!/usr/bin/env python3
from collections import Counter, defaultdict
from pathlib import Path
import sys


def read_unique_ips_and_domains(
    file_path: Path,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    unique_ips, unique_domains = defaultdict(set), defaultdict(set)
    for line in file_path.read_text().splitlines():
        line_split = line.split(";")
        domain = line_split[0]
        ip = line_split[1]

        unique_ips[ip].add(file_path.name)
        unique_domains[domain].add(file_path.name)

    return unique_ips, unique_domains


def main():
    dir_path = Path(sys.argv[1])
    domain_counter = Counter()
    ip_counter = Counter()

    domains_in_file = defaultdict(set)
    ip_in_file = defaultdict(set)

    for file_path in dir_path.glob("*resolved_domains.csv"):
        ips, domains = read_unique_ips_and_domains(file_path)
        domain_counter.update(domains.keys())
        ip_counter.update(ips.keys())

        for ip in ips:
            ip_in_file[ip].add(file_path.name)

        for domain in domains:
            domains_in_file[domain].add(file_path.name)

    print("Most common domains:")
    print(domain_counter.most_common(100))
    print(ip_counter.most_common(100))

    print({f"{k}: {v}" for k, v in domains_in_file.items() if len(v) > 1})


if __name__ == "__main__":
    main()
