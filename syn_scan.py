from scapy.layers.inet import TCP, IP, report_ports
from scapy.sendrecv import send, sr

def scan(dest_ip):
    # send TCP SYN to ports 1 - 1024
    ans,unans=sr(IP(dst=dest_ip)/TCP(flags='S', dport=(1, 1024)))

    # display ports which returned SYN/ACK
    for packet in ans:
        if 'flags=SA' in str(packet):
            print(str(packet).split(' ')[7])


