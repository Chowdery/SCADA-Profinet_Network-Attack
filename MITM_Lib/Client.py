__author__ = 'Nicholas Rodofile'

import Queue
from Injection import *

import snap7
from snap7.snap7types import*
from snap7.util import*

#Parent Class
class Client(object):
    def __init__(self, node, port, timeout_time=2*60):
        self.node = node
        self.address = node.ip_address      #Victim IP address
        self.port = port                    #Victim port
        self.size = 100
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.queue_in = Queue.Queue()       #Incoming packet queue
        self.queue_out = Queue.Queue()      #Outgoing packet queue
        self.error = False
        self.running = False                #Set to True when successful socket opened
        self.timeout_time = timeout_time
        self.s7_client = snap7.client.Client()

    def connect(self):
        try:
            self.socket.connect((self.address, self.port))
            print "Connecting to", self.address, "via port", self.port
        except socket.error, exc:
            print "Client Connect: Caught exception socket.error : %s" % exc
            self.running = False
            self.error = True
            return False
        self.running = True
        return True

    def send(self, data):
        if self.running:
            try:
                self.socket.send(str(data))
            except socket.error, exc:
                print "Client Send: Caught exception socket.error : %s" % exc
                self.running = False
                self.socket.close()

    def receive(self):
        while self.running:
            try:
                data = self.socket.recv(self.size)
                if data:
                    self.queue_in.put(data)
                else:
                    self.socket.close()
                    self.running = False
            except socket.error, exc:
                print "Client Recv: Caught exception socket.error : %s" % exc
                self.running = False
                self.socket.close()
        print "- Closing Listener..."

    def process_in(self):
        print "- Running in Process..."
        while self.running:
            if not self.queue_in.empty():
                data = self.queue_in.get()
                self.queue_in.put(data)
            else:
                pass
        print "- Quiting in Process..."

    def process_out(self):
        print "- Running out Process..."
        while self.running:
            if not self.queue_in.empty():
                data = Raw(load=self.queue_in.get())
                parsed = TCP(sport=self.port)/data
                print parsed.summary()
                self.send("Hello")
            else:
                pass
        print "- Quiting out Process..."

    def stop(self):
        if self.running:
            self.running = False
            print "Quiting program..."
            try:
                self.socket.shutdown(socket.SHUT_WR)
                #self.s7_client.disconnect()
            except socket.error, exc:
                print "Client Recv: Caught exception socket.error : %s" % exc

    def quit(self):
        while self.running:
            option = str(raw_input("Enter \'Q\' to Quit\n"))
            if option == 'q' or option == 'Q':
                self.stop()

    def timeout(self):
        while not self.running:
            pass
        #sleep(self.timeout_time)
        while self.running:
            pass
        if self.running:
            print "- Time Up ..."
            self.running = False
            sleep(10)
        print "Quitting timer"

    def start(self):
        processor_in = Thread(target=self.process_in)
        processor_out = Thread(target=self.process_out)
        terminator = Thread(target=self.quit)
        listener = Thread(target=self.receive)
        timer = Thread(target=self.timeout)
        terminator.daemon = True
        listener.daemon = True
        if self.connect():
            terminator.start()
            processor_in.start()
            processor_out.start()
            listener.start()
            timer.start()
            timer.join(2)
            processor_in.join(2)
            processor_out.join(2)
            terminator.join(2)
            listener.join(2)
            return True
        else:
            return False


# mitm = MITM_conf(pkt_count="100")
# mitm.init_spoofing()
# victim = mitm.victim
# client = Client(victim, 20000)
# client.start()
