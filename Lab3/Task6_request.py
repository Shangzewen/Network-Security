from scapy.all import *


def GenerateQueryPkt():
    targetName = 'abcde.example.com'
    IPpkt = IP(dst='10.0.2.8', src='10.0.2.9')
    # can set source port to any port number
    UDPpkt = UDP(dport=53, sport=1234, chksum=0)
    Qdsec = DNSQR(qname=targetName)
    dnspkt = DNS(id=0xaaaa,
                 qr=0,
                 qdcount=1,
                 ancount=0,
                 nscount=0,
                 arcount=0,
                 qd=Qdsec)
    Querypkt = IPpkt / UDPpkt / dnspkt
    with open('ip_req.bin', 'wb') as f:
        f.write(bytes(Querypkt))


GenerateQueryPkt()