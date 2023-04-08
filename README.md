# scapy-tools

## syn-scan.py
Small script for scanning a target host for open TCP ports. It sends a TCP
SYN packet to the selected TCP ports and prints an overview of the listening
ports. A bit like the nmap SYN scan (-sS).

### Usage
```
# ./syn-scan.py -t 192.168.1.133 -p 21 22 80 443
```

## syn-flood.py
Keeps creating half-open connections on the specified host until the script is
manually stopped. The target ports is by default 80 and 443, but they can be
changed in the script.

### Usage
```
# ./syn-flood.py -t 192.168.1.133
```

## traffic-sniffer.py
Sniffs packets from the selected interface using Scapy's sniff function.

### Usage
```
# ./traffic-sniffer.py -o my_captured_packets.py
```

## pcap-summary.py
Reads a packet capture file (pcap) and creates an overview of the packet count
in two CSV files containing lines for each IP and service port.

### Usage:
```
$ ./pcap-summary.py -f capture.pcapng -ips 192.168.1.10 -d ./results
```

### Arguments explained
* __-f or --pcap-file__: Packet capture (required).
* __-ips__: IPs to exclude from the CSV files (required).
* __-d or --output-dir__: Output directory where the CSV files are created
* (optional, default: current directory).
