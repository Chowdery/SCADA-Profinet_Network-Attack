__author__ = 'Nicholas Rodofile'

from DNP3_Lib_MITM import *

#pkt = "\x05\x64\x06\x80\xc8\x00\x64\x00\x1f\x62"
#print hex(crcDNP(pkt[:8]))
##print hex(crcDNP("\x05\x64\x80\xc8\x00\x64\x00"))
#print hex(crcDNP("\x05\x64\x06\x80\xc8\x00\x64\x00\x1f\x62"))
#print hex(crcDNP("\x05\x64\x06\x80\xc8\x00\x64\x00\x1f\x62"))
#print hex(crcDNP("\x05\x64\x06\x80\xc8\x00\x64\x00\x1f\x62"))
#print hex(crcDNP("\x05\x64\x06\x80\xc8\x00\x64\x00\x1f\x62"))

#print hex(crcDNP("\xc1\xf1\x01"))

attackerIP = "192.168.56.7"
attackerMAC = "08:00:27:28:ca:9f"

masterIP = "10.192.228.5"
masterMAC = "00:30:a7:02:80:e2"

slaveIP = "10.192.226.19"
slaveMAC = "00:18:64:00:15:b8"

masterARP = ""
slaveARP = ""

pkts = rdpcap('4_14_3_button_press_SEL_no_attack.pcap')
#pkts = rdpcap('debug_DNP3.pcap')

i = 1
for p in pkts:
    print i
    p.show2()
    i += 1
