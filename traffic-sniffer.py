#!/usr/bin/env python3
from scapy.all import sniff, wrpcap


INTERFACE="en0"
FILTER="tcp port 443 or tcp port 80"
OUTPUT="capture.pcap"

def show_packet(packet):
    # TODO: add filtering if needed!
    print(packet.show())


def main():
     packets = sniff(iface=INTERFACE, filter=FILTER, prn=show_packet)
     wrpcap(OUTPUT, packets)


if __name__ == "__main__":
    main()

