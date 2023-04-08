# scapy-tools

## syn_scan.py
Small script for scanning a target host for open TCP ports. It sends a TCP
SYN packet to the selected TCP ports and prints an overview of the listening
ports. A bit like the nmap SYN scan (-sS).

### Usage
```
# ./syn_scan.py -t 192.168.1.133 -p 21 22 80 443
```

## syn_flood.py
Keeps creating half-open connections on the specified host until the script is
manually stopped. The target ports is by default 80 and 443, but they can be
changed in the script.

### Usage
```
# ./syn_flood.py -t 192.168.1.133
```

## arp_poison.py
Tool for ARP cache poisoning. Can be helpful when you need to sniff network traffic 
to/from a host on your local network.

### Usage
```
# ./arp_poison.py -t 192.168.1.133 -g 192.168.1.1 -i eth0
```

## traffic_sniffer.py
Sniffs packets from the selected interface using Scapy's sniff function.

### Usage
```
# ./traffic_sniffer.py -o my_captured_packets.py
```

## pcap_summary.py
Reads a packet capture file (pcap) and creates an overview of the packet count
in two CSV files containing lines for each IP and service port.

### Usage:
```
$ ./pcap_summary.py -f capture.pcapng -ips 192.168.1.10 -d ./results
```

### Arguments explained
* __-f or --pcap-file__: Packet capture (required).
* __-ips__: IPs to exclude from the CSV files (required).
* __-d or --output-dir__: Output directory where the CSV files are created
* (optional, default: current directory).
