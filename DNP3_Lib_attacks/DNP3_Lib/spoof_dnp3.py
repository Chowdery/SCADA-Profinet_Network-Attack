__author__ = 'Nicholas Rodofile'
from DNP3_Lib_ import *
from random import randrange

dst_ip = "192.168.56.3"
dst_mac = "08:00:27:44:c5:60"
#src_mac = "08:00:27:57:02:a0"

master_address = 1
slave_address = 10

seq = randrange(1000)

ip=IP(src=None, dst=dst_ip)
TCP_SYN=TCP(sport=dnp3_port, dport=dnp3_port, flags="S", seq=seq)
print TCP_SYN.summary

TCP_SYNACK=sr1(ip/TCP_SYN)

seq += 1
my_ack = TCP_SYNACK.seq + 1
TCP_ACK=TCP(sport=dnp3_port, dport=dnp3_port, flags="A", seq=2, ack=my_ack)
send(ip/TCP_ACK)

chunk1="\xc1\xc1\x03\x0c\x01\x28\x01\x00\x01\x00\x03\x01\x64\x00\x00\x00\x7b\x5e"
chunk2="\xc1\xc1\x03\x0c\x01\x28\x01\x00\x01\x00\x03\x01\x64\x00\x00\x00\x7b\x5e"
#dnp3_pay = DNP3(DESTINATION = 1, SOURCE = 2, CONTROL = DNP3HeaderControl(PRM = MASTER, DIR = MASTER, DFC = SET, FUNC_CODE_PRI = 4))/DNP3Transport(FIN = UNSET, FIR = SET, SEQUENCE = 1)/DNP3ApplicationRequest()
dnp3_pay = DNP3(DESTINATION = slave_address, SOURCE = master_address, CONTROL = DNP3HeaderControl(PRM = MASTER, DIR = MASTER, DFC = SET, FUNC_CODE_PRI = 5))/chunk1/chunk2

seq += 1
TCP_PUSH=TCP(sport=dnp3_port, dport=dnp3_port, flags="PA", seq=seq, ack=my_ack)
dnp3_pay.show2()

#send(ip/TCP_PUSH/dnp3_pay)

for s in range(4):
    TCP_PUSH=TCP(sport=dnp3_port, dport=dnp3_port, flags="PA", seq=seq, ack=my_ack)
    send(ip/TCP_PUSH/dnp3_pay)
    seq += 1


TCP_FIN=TCP(sport=dnp3_port, dport=dnp3_port, flags="FA", seq=seq, ack=my_ack)
