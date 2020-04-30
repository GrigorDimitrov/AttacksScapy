#!/usr/bin/python
from scapy.all import *
from scapy.layers.http import http_request
from scapy.layers.inet import IP, TCP

# "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 80 -j DROP"
# "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 80 -j DROP"

load_layer("http")
ans = http_request("192.168.198.130", "/page=forum-server/fs-admin/fs-admin.php?groupid=<script>")

