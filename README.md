# Ophidia
ARP Poisoning attack script using Python and Scapy

# Dependencies
[Scapy](scapy.net)
Python 3

# Configuration

You need to enable IPv4 forwarding on your machine. For UNIX-like OSs simply run with root privileges:

```
sysctl -w net.ipv4.ip_forward=1
```

# Usage

Run

```
python main.py [victim IP] [gateway IP] [net interface]
```

with root privileges. A `ophidia.pcap` file will be created with 200 captured packets. You can then use a tool like Wireshark to analyze such packets.
