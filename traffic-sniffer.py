#!/usr/bin/env python3
from scapy.all import sniff


INTERFACE="en0"
FILTER="tcp port 443 or tcp port 80"


def show_packet(packet):
    # TODO: add filtering if needed!
    print(packet.show())


def main():
     sniff(iface=INTERFACE, filter=FILTER, prn=show_packet, store=0)


if __name__ == "__main__":
    main()

