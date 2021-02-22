from scapy.all import *


def SendPacket():
    IPpkt = IP(dst='10.0.2.8', src='10.0.2.9')
    UDPpkt = UDP(dport=53, sport=2222, chksum=0)
    Qdsec = DNSQR(qname='www.example.com')
    dnspkt = DNS(id=0xaaaa,
                 qr=0,
                 qdcount=1,
                 ancount=0,
                 nscount=0,
                 arcount=0,
                 qd=Qdsec)
    Requestpkt = IPpkt / UDPpkt / dnspkt
    send(Requestpkt)


SendPacket()