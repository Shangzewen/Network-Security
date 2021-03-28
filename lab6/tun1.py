#!/usr/bin/python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
# create TUN interface
tun = os.open("/dev/net/tun", os.O_RDWR)
# ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
# change the name of the tun interface
ifr = struct.pack('16sH', b'zewen', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface name : {}".format(ifname))

# while (True):
#     time.sleep(10)
while (True):
    packet = os.read(tun, 2048)
    if True:
        ip = IP(packet)
        ip.show()