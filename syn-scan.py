#!/usr/bin/env python3
from argparse import ArgumentParser
from scapy.all import IP, TCP, RandShort, sr


def parse_arguments():
    parser = ArgumentParser(description="Reads PCAP file and prints summary.")
    parser.add_argument("-t", "--target", dest="target", type=str, required=True)
    parser.add_argument("-p", "--ports", dest="ports", type=int, nargs="*", required=True)

    return parser.parse_args()


def main():
    args = parse_arguments()

    ports_str = ", ".join((str(x) for x in args.ports))
    print(f"Target: {args.target} TCP ports {ports_str}")

    packets = IP(dst=args.target)/TCP(sport=RandShort(), dport=args.ports, flags="S")
    answered, unanswered = sr(packets, inter=0.2, timeout=1, retry=1)

    print(answered.nsummary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA"))
    print("Scan finished!")


if __name__ == '__main__':
    main()

