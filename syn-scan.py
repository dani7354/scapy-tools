#!/usr/bin/env python3
from argparse import ArgumentParser
from scapy.all import IP, TCP, sr


ports = [21, 22, 80, 443, 445, 3306, 8080]


def parse_arguments():
    parser = ArgumentParser(description="Reads PCAP file and prints summary.")
    parser.add_argument("-t", "--target", dest="target", type=str, required=True)

    return parser.parse_args()


def main():
    args = parse_arguments()
    packets = IP(dst=args.target)/TCP(dport=ports, flags="S")
    answered, unanswered = sr(packets, inter=0.2, timeout=1, retry=1)
    print(answered.summary())
    print("Scan finished!")


if __name__ == '__main__':
    main()

