#!/usr/bin/python
from scapy.all import *
from scapy.layers.http import http_request
from scapy.layers.inet import IP, TCP
import random
# "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 80 -j DROP"
# "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 80 -j DROP"

def sql(src_ip, dst_ip):
    
    # Generating the IP layer:
    ip=IP(src=src_ip, dst=dst_ip)
    
    # Generating TCP layer:
    SYN = TCP(sport = random.randint(1,65535), dport=80)
    
    #send SYNACK to remote host AND receive ACK.
    ANSWER=sr1(ip/SYN)

    # send ACK
    TCP_ACK=TCP(sport=ANSWER.dport, dport=80, flags="A", seq=ANSWER.ack, ack=ANSWER.seq+1)
    send(ip/TCP_ACK)

    # Malicious request
    html = 'GET / insert into HTTP/1.1\r\n' \
       'Host: developer.cdn.mozilla.net\r\n' \
       'Connection: close\r\n\r\n' 
    send(ip/TCP_ACK/html)
    
    # The End
