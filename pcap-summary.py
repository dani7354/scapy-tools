from scapy.all import rdpcap, PacketList, IP, TCP, UDP
from argparse import ArgumentParser
import collections
import os
import time


PacketInfo = collections.namedtuple("PacketInfo", ["src_ip", "dst_ip", "src_port", "dst_port"])


def parse_arguments():
    parser = ArgumentParser(description="Reads PCAP file and prints summary.")
    parser.add_argument("-f", "--pcap-file", dest="pcap_file", type=str, required=True)
    parser.add_argument("-ips", "--local-ips", dest="local_ips", type=str,
    nargs="*", required=False)
    parser.add_argument("-d", "--output-dir", dest="output_dir", type=str,
    required=False, default="./")

    return parser.parse_args()


def get_tcp_and_udp(pcap_file: str) -> tuple:
    tcp = []
    udp = []
    for p in rdpcap(pcap_file):
        if IP not in p:
            continue
        src_ip = p[IP].src
        dst_ip = p[IP].dst
        if TCP in p:
            tcp.append(PacketInfo(src_ip=src_ip, dst_ip=dst_ip,
            src_port=p[TCP].sport, dst_port=p[TCP].dport))
        elif UDP in p:
            udp.append(PacketInfo(src_ip=src_ip, dst_ip=dst_ip,
            src_port=p[UDP].sport, dst_port=p[UDP].dport))

    return tcp, udp


def create_or_update_ip(summary: dict, ip: str, port: str):
    if ip not in summary:
        summary[ip] = {}
    if port not in summary[ip]:
        summary[ip][port] = 1
    else:
        summary[ip][port] += 1


def get_summary_by_ip(packets: list, local_ips: set) -> dict:
    ports_by_ip = {}
    for p in packets:
        if p.src_ip not in local_ips:
            create_or_update_ip(ports_by_ip, p.src_ip, p.src_port)
        elif p.dst_ip not in local_ips:
            create_or_update_ip(ports_by_ip, p.dst_ip, p.dst_port)

    for ip, ports in ports_by_ip.items():
        ports_by_ip[ip] = dict(sorted(ports.items(), key=lambda x: x[1],
        reverse=True))

    return dict(sorted(ports_by_ip.items(), key=lambda x: sum(y for y in
    x[1].values()), reverse=True))


def write_csv(file: str, packets: dict):
    with open(file, "w") as csv_file:
        csv_file.write("ip;port;packets\n")
        for ip, ports in packets.items():
            for port, count in ports.items():
                csv_file.write(f"{ip};{port};{count}\n")


def main():
    args = parse_arguments()
    local_ips = set(args.local_ips)
    local_ips_str = ", ".join(local_ips)
    print(f"Local IPs to exclude: {local_ips_str}")

    tcp, udp = get_tcp_and_udp(args.pcap_file)
    tcp_summary = get_summary_by_ip(tcp, local_ips)
    udp_summary = get_summary_by_ip(udp, local_ips)
    print(f"TCP packets: {len(tcp)}")
    print(f"UDP packets: {len(udp)}")

    time_seconds = int(time.time())
    tcp_csv = os.path.join(args.output_dir, f"tcp_{time_seconds}.csv")
    udp_csv = os.path.join(args.output_dir, f"udp_{time_seconds}.csv")

    print(f"Writing TCP packet count to {tcp_csv}")
    write_csv(tcp_csv, tcp_summary)
    print(f"Writing UDP packet count to {udp_csv}")
    write_csv(udp_csv, udp_summary)


if __name__ == '__main__':
    main()

