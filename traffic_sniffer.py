#!/usr/bin/env python3
from argparse import ArgumentParser, Namespace
from scapy.all import sniff, wrpcap
import time


packets = []


def get_default_pcap():
    time_seconds = int(time.time())
    return f"capture_{time_seconds}.pcap"


def parse_arguments() -> Namespace:
    parser = ArgumentParser(description="Sniffs packets and saves them to pcap")
    parser.add_argument("-i", "--interface", dest="interface", type=str, required=False, default="any")
    parser.add_argument("-f", "--filter", dest="filter", type=str, required=False, default="")
    parser.add_argument("-o", "--output", dest="output", type=str, required=False, default=get_default_pcap())

    return parser.parse_args()


def save_packet(packet):
    packets.append(packet)
    print(packet.summary())


def main():
    args = parse_arguments()

    print(f"Sniffing packets on interface {args.interface} with filter {args.filter}...")
    sniff(iface=args.interface, filter=args.filter, prn=save_packet, store=0)

    print(f"Saving captured packets to {args.output}...")
    wrpcap(args.output, packets)


if __name__ == "__main__":
    main()
