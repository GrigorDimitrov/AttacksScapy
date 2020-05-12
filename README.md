# AttacksScapy Tutorial
The main idea is generating malicious traffic for analysts training. Scapy s used to simulate realistic attacks. The attacks are picked up by an IDS. This tool serves as a cyber-range where analysts can learn how to identify cyber-attacks.
This tutorial is the second part of an analysts training framework. Part one can be found here https://github.com/GrigorDimitrov/sop  
Scapy is a Python package used to generate malicious traffic. Analysts can launch attack scripts between VMs. Security Onion is monitoring the traffic. The attacks are matched by Snort rules and alerts are generated.

## Creating Virtual Machines
Download Metasploitable2 from here https://sourceforge.net/projects/metasploitable/files/Metasploitable2/. 
Download Kali Linux from here http://www.kali.org/downloads/  
Make sure Metasploitable is on the Host-Only network as it is a vulnerable Linux machine. Kali Linux should have 2 network interfaces – NAT and Host-Only. 
Run the VMs and try pinging between them. Verify network connectivity on Kali.
>ping 8.8.8.8

## Downloading Scripts
The attacks scripts can be downloaded from GitHub. Open a terminal on Kali and type in:
>sudo git pull https://github.com/GrigorDimitrov/AttacksScapy.git

Scapy is required to run the tool. Kali Linux should have Python 3 installed.
>sudo pip install --pre scapy[basic]

Change directory to AttacksScapy and run attack.py.
>sudo python3 attack.py

You will be presented with instructions regarding the tool usage. The Linux kernel automatically sends RST packets when a packet is sent or received unexpectedly. This behaviour might interrupt the attacks. RST packets can be blocked with Iptables.
>sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 80 -j DROP
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 80 -j DROP

## Running Attacks
Different attacks require different parameters. For example, SYN Flood attack can be launched by specifying the target IP address using -dip tag (destionation IP). The script will send 1000 SYN packets to different ports on Metasploitable. This will generate an alert in Security Onion.
>sudo python3 attack.py -dip 192.168.204.129 -a flood

Go to Security Onion and open Sguil. Notice the “TCP SYN flood attack detected” alert. Open a transcript of the event to see more details about the attack.
