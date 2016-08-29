from MITM_Lib.Client import *

#Child class of Client
#Parent class for all attack methods
class Step7_Master(Client):
    def __init__(self, node, port, timeout_time=2*60):
        Client.__init__(self, node, port, timeout_time=timeout_time)

    #Extract the raw (PDU) data, determine response and add to the outgoing packets
    def process_response(self, response):
        print response
        # Process response using Snap 7 lib
        condition = False       #Change this based on processing code
        if condition:
            self.queue_out.put("data")

    #Process the incoming packets
    def process_in(self):
        print "- Running in Process..."
        while self.running:
            if not self.queue_in.empty():
                try:
                    data = self.queue_in.get()
                    self.process_response(data)
                except:
                    raise
            else:
                pass
        print "- Quiting in Process..."

    #Process the outgoing packets
    def process_out(self):
        print "- Running out Process..."
        while self.running:
            if not self.queue_out.empty():
                step7 = self.queue_out.get()
                # print step7.summary()
                self.send(step7)
            else:
                pass

        print "- Quiting out Process..."

    def automation(self):
        sleep(20)
        if self.running:
            self.stop()

    def start(self):
        automation = Thread(target=self.automation)
        automation.daemon = True
        automation.start()
        super(Step7_Master, self).start()
        automation.join()
        self.socket.close()
        self.queue_out = None
        return


class Step7_Master_Replay(Step7_Master):
    def __init__(self, node, port, pcap=None, timeout_time=2 * 60):
        Step7_Master.__init__(self, node, port, timeout_time=timeout_time)
        self.pcap = rdpcap(pcap)
        self.replay_messages = list()

    def filter_pcap(self):
        for p in self.pcap:
            # filter conditions
            pass

    def replay(self):
        print len(self.replay_messages), "Replayable Packets"
        m = self.replay_messages[0]
        wait_time = m.time
        #self.queue_out.put(m[DNP3])
        for m in self.replay_messages[1:]:
            sleep_time = m.time - wait_time
            time.sleep(sleep_time)
            #self.queue_out.put(m[DNP3])
            wait_time = m.time

    def automation(self):
        self.filter_pcap()
        while not self.running:
            pass

        if self.running:
            self.replay()
        self.stop()