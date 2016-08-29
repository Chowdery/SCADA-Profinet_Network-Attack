__author__ = 'Nicholas Rodofile'
from DNP3_Lib_ import *

dst_ip = "192.168.56.3"
dst_mac = "08:00:27:44:c5:60"
src_mac = "08:00:27:57:02:a0"

port = 20000
seq = 0

ip=IP(src=None, dst=dst_ip)
SYN=TCP(sport=port,dport=port, flags="S", seq=seq)
packet=ip/SYN
SYNACK=sr1(packet)

my_ack=SYNACK.seq+1
ACK = TCP(sport=port,dport=port, flags="A", seq=seq, ack=my_ack)
send(ip/ACK)
seq += 1

PUSH=TCP(sport=port, dport=port, flags="PA", seq=seq, ack=my_ack)
data = "SEND THIS!"
PUSH_ACK = sr1(ip/PUSH/data)
seq += 1

PUSH=TCP(sport=port, dport=port, flags="PA", seq=seq, ack=my_ack)
data = "SEND this as well"
send(ip/PUSH/data)
seq += 1