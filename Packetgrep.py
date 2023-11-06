#N7y
import argparse
import os
import sys


if os.getuid() != 0:
    print("Need root privlliage to start")
    exit()
from scapy.all import *


parser = argparse.ArgumentParser(description='Detect and capture certain type of packet and malicious behaivor at real time;')

parser.add_argument('--http', help='Listen n capture for http data',action='store_true')
parser.add_argument('--ftp', help='Listen for ftp data',action='store_true')
parser.add_argument('--icmp', help='Listen for icmp packet',action='store_true')
parser.add_argument('--telnet', help='Listen for telnet data',action='store_true')
parser.add_argument('--dns', help='Listen for dns data',action='store_true')
parser.add_argument('--arp', help='Listen for ARP',action='store_true')
parser.add_argument('--dnsq', help='Listen for dns query packets',action='store_true')
parser.add_argument('--dpscan', help='Detect port scan; we look for ip that is trying to connect with d/f port of us',action='store_true')
parser.add_argument('--darpspoof', help='Detects for spoofing',action='store_true')
parser.add_argument('--getmc', help='Get mac with ip')
parser.add_argument('--getip', help='GET ip with mac')
parser.add_argument('--watch', help='capture packets with specific port',type=int)
parser.add_argument('--outgoing', help='capture packets that are out going',action='store_true')
parser.add_argument('--incoming', help='capture packets that are in coming',action='store_true')
parser.add_argument('--iface',help="Interface to use ")


args = parser.parse_args()

if len(sys.argv) == 1:
    print("""
            \r \r  Tool detect and capture certain type of packet and malicious behaivor at real time
\t\t\t\t\t Auther: N7y

[...     [..                   
[. [..   [..[..... [..         
[.. [..  [..      [.. [..   [..
[..  [.. [..     [..   [.. [.. 
[..   [. [..    [..      [...  
[..    [. ..    [..       [..  
[..      [..    [..      [..   
                       [..  

    \r Usage is very human just
    \r python3 Packetgrep.py --help

        """)
    exit()





if not args.iface:
    print("--iface wlan0")
    print("Interface needed to work with exiting...")
    exit()
else:
    iface = args.iface


try:
    ip = get_if_addr(iface)
except:
    print("Error with Interface :",iface)
    exit()

def ipformat(ip):
        try:
            if len(ip.split('.')) == 4:
                return True
            else:
                return False
        except:
            return False

def macformat(mac):
        try:
            if len(mac.split(':')) == 6:
                return True
            else:
                return False
        except:
            return False
def ht(p):
    # print(packet.summary())
    for packet in p:
    	if packet.haslayer(TCP) and packet.haslayer(Raw):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                http_ = packet[Raw].load.decode('utf-8', errors='ignore')
                if 'HTTP' in http_:
                    print(packet[IP].src,' -> ', packet[IP].dst,' HTTP')
                    print(http_)

            
                # print(packet[TCP].payload)
def ips(p):
    for packet in p:
        if IP in packet:
            print(packet[IP].src,' -> ', packet[IP].dst)

def ftp(p):
    for packet in p:
            if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    print(packet[IP].src,' -> ', packet[IP].dst,'  PORT 21 FTP')
                    print(packet[Raw].load.decode())
def tlnt(p):
    for packet in p:
            if packet[TCP].dport == 23 or packet[TCP].sport == 23:
                    print(packet[IP].src,' -> ', packet[IP].dst,'  PORT 23 TELNET')
                    print(packet[Raw].load.decode())
def dnsq(p):
    for packet in p:
            if DNSQR in packet:
                print(packet[DNSQR].qname.decode()) 
def icmp(p):
        for packet in p:
            if ICMP in packet:
                print("ICMP from: ", packet[IP].src)  
def tcps(p):
    for packet in p:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            print("src mac addr :",packet[Ether].src)
            print("src IP:", packet[IP].src)
            print("dst IP:", packet[IP].dst)
            print("src port:", packet[TCP].sport)
            print("dst port:", packet[TCP].dport)
            print("summary:", packet.summary())            

def arp(p):
    for packet in p:
        if ARP in packet:
            print(f"sender : {p[ARP].psrc} : {p[ARP].hwsrc} >>>>> recver {p[ARP].pdst} : {p[ARP].hwdst} ")

def dns(p):
    for packet in p:  
        if DNS in packet:
            print(packet.summary)


def getmc(ip):
    arprq = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    arpr = srp(arprq,timeout=5)[0]
    if arpr:
        mcaddr = arpr[0][1].hwsrc
        return mcaddr
    else:
        return "Unabel to get mac"

def getip(mac):
    router = os.popen("route -n | grep "+iface+" | head -1 | awk '{print $2}'").read().strip()
    cider = os.popen("ip a | grep "+iface+" | grep inet | awk '{print $2}'").read().strip().split('/')[-1]

    net_addr = router+'/'+cider
    print("\tNetwork addr: ",net_addr)
    ret = arping(net_addr)
    print(ret)

   

def inc(p):
    for packet in p:
        if IP in packet:
            if packet[IP].src != ip:
                if TCP in packet:
                    print("IP ",packet[IP].src," to port ",packet[TCP].dport)
                else:
                    print("IP ",packet[IP].src)
def out(p):
    for packet in p:
        if IP in packet:
            if packet[IP].src == ip:
                print("src : ",packet[IP].src, "-> " ,"dst : " , packet[IP].dst)
        


ip_hist = []
stor = {}
ip = get_if_addr(iface)
c = 0
def det_pscn(packet):
    global c
    packet_size = len(bytes(packet))
    print(packet.show())
    if IP in packet:
        # print(set(ip_hist))
        # print(ip_hist)
        if TCP in packet:
            if packet[IP].src != ip:
                c = c + 1
                src_ip = packet[IP].src
                # {
                # 'ip':[[80,433,8080],[3]],

                # } d[ip][0] ports        , d[ip][1] counts
                #   d[ip][0].append(p),    , d[ip][1][0] + 1
                if c == 1:
                    stor[str(src_ip)] = [[packet[TCP].dport],[1]]
                    ip_hist.append(src_ip)
                    print("first",stor)

                if src_ip in ip_hist:
                    dport = packet[TCP].dport
                    # print("checking if ",dport," in ",stor[src_ip][0])
                    if dport in stor[src_ip][0]:
                        # print(stor[src_ip][0]," alrady there")
                        pass 
                    else:
                        # print("Incrementing and Appending : ",stor[src_ip][0])
                        stor[str(src_ip)][0].append(packet[TCP].dport)
                        stor[str(src_ip)][1][0] += 1

                    if stor[str(src_ip)][1][0] > 100:
                        print("Found sus ip : ", src_ip," doing connect more than 100 with d/f port;",stor)
                    
                   
                    
                # print(stor)

def det_arpspf(p):
    if p.haslayer(ARP):
        if p[ARP].op == 2:
            packet_mac = p[ARP].hwsrc
            packet_ip = p[ARP].psrc
            packet_ip_mac = getmc(packet_ip)

            if packet_ip_mac != packet_mac:
                print("arp spoofing activity found  packet: ",packet_mac,"checked mac :",packet_ip_mac)



if args.http:
    print("\n\tCapturing any http data on",iface)
    sniff(iface=iface, prn=ht, filter='tcp')
elif args.watch:
    port = args.watch
    def wtch(p):
        for packet in p:
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                if packet[TCP].dport == port or packet[TCP].sport == port:
                    print(packet.summary())
    if str(port).isnumeric():
        print("\n\tCapturing any TCP  with port ",port," on ",iface)
        sniff(iface=iface, prn=wtch, filter='tcp')

    else:
        print("invalid port")
        exit()


elif args.ftp:
    print("\n\tCapturing any ftp data on",iface)
    sniff(iface=iface, prn=ftp, filter='tcp')
elif args.dns:
    print("\n\tCapturing any dns on",iface)
    sniff(iface=iface, prn=dns)
elif args.icmp:
    print("\n\tCapturing any icmp on",iface)
    sniff(iface=iface, prn=dns)
elif args.arp:
    print("\n\tCapturing any arp on",iface)
    sniff(iface=iface, prn=arp)
elif args.telnet:
    print("\n\tCapturing any Telnet data on",iface)
    sniff(iface=iface, prn=tlnt)
elif args.dnsq:
    print("\n\tCapturing any Dns query on",iface)
    sniff(iface=iface, prn=dnsq)
elif args.dpscan:
    print("\n\tDetecting Port Scan  on",iface)
    sniff(iface=iface, prn=det_pscn, filter='tcp')
elif args.darpspoof:
    print("\n\tDetecting spoofing  on",iface)
    sniff(iface=iface, prn=det_arpspf,filter='arp')
elif args.getmc:
    ip = args.getmc
    if ipformat(ip):
        print("\n\tLooking mac of ",ip," on ",iface)
        mc = getmc(ip)
        print("MAC of ",ip," :",mc)
    else:
        print("invalid ip format")
elif args.getip:
    mc = args.getip
    if macformat(mc):
        print("\n\tLooking ip of ",mc," on ",iface)
        getip(mc)
        
    else:
        print("invalid mac format")
elif args.watch:
    port = args.getip
    print("do watch : ",port)
elif args.outgoing:
    print("\n\tCapturing for outgoing on ",iface)
    sniff(iface=iface, prn=out)
elif args.incoming:
    print("\n\tCapturing for incoming on ",iface)
    sniff(iface=iface, prn=inc)





# print("..")
# sniff(iface='wlan0', prn=ht, filter='tcp')










# p.py --http,--ftp,--dns,--dnsq, --dpscan -darpspoof --getmc --getip --watch [port] --outgoing --incoming
#
