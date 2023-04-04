#!/usr/bin/python3
from scapy.all import send, IP, TCP, RandIP, RandShort, sr, sr1, send

TARGET = "192.168.1.1"
ports = [21, 22, 80, 443, 445, 3306, 8080]


packets = IP(dst=TARGET)/TCP(dport=ports, flags="S")

answered, unanswered = sr(packets, inter=0.2, timeout=1, retry=1)
print(answered.summary())
print("Scan finished!")
