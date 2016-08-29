__author__ = 'Nicholas Rodofile'

import Queue
from Injection import *
from scapy.all import *
import atexit

class Server(object):
    def __init__(self, node, port, timeout_time=(60 * 2)):
        self.node = node
        self.address = node.ip_address
        self.port = port
        self.size = 1024
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.queue_in = Queue.Queue()
        self.queue_out = Queue.Queue()
        self.error = False
        self.running = False
        self.connection = None
        self.timeout_time = timeout_time

    def close_connection(self):
        self.running = False
        if self.connection is not None:
            self.connection.close()
        print "- Closed Connection"

    def close_socket(self):
        self.running = False
        self.socket.close()
        print "- Closed Socket"

    def listen(self):
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('', self.port))
            self.socket.listen(1)
            self.socket.settimeout(10) #set time out to 10 seconds
            conn, client_address = self.socket.accept()
            self.connection = conn
            #atexit.register(self.connection.close())
            print "Connected by", client_address
            return True
        except socket.error, exc:
            print "Server.listen Caught exception socket.error : %s" % exc
            self.running = False
            self.error = True
            return False

    def send(self, data):
        try:
            if self.running:
                self.connection.send(str(data))
        except socket.error, exc:
            print "Server.send Caught exception socket.error : %s" % exc
            self.running = False
            self.socket.close()

    def receive(self):
        try:
            while self.running:
                data = self.connection.recv(self.size)
                if data:
                    self.queue_in.put(data)
                else:
                    self.socket.close()
                    self.running = False
        except socket.error, exc:
            print "Server.receive Caught exception socket.error : %s" % exc
            self.running = False
            self.socket.close()
        print "- Closing Listener..."

    def timeout(self):
        while not self.running:
            pass
        sleep(self.timeout_time)
        if self.running:
            print "- Time Up ..."
            self.running = False
            sleep(10)

    def process_in(self):
        print "- Running in Process..."
        while self.running:
            if not self.queue_in.empty():
                self.timeout_time = time.time() + 10
                data = self.queue_in.get()
                self.queue_in.put(data)
            else:
                pass
        print "- Quiting in Process..."

    def process_out(self):
        print "- Running out Process..."
        while self.running:
            if not self.queue_in.empty():
                data_in = self.queue_in.get()
                if data_in is not None:
                    data = Raw(load=data_in)
                    parsed = TCP(sport=self.port)/data
                    print parsed.summary()
                    self.send("Hello")
            else:
                pass
        print "- Quiting out Process..."

    def quit(self):
        while self.running:
            option = str(raw_input("Enter \'Q\' to Quit\n"))
            if option == 'q' or option == 'Q':
                if self.running:
                    self.running = False
                    print "Quiting program..."

    def start(self):
        processor_in = Thread(target=self.process_in)
        processor_out = Thread(target=self.process_out)
        terminator = Thread(target=self.quit)
        listener = Thread(target=self.receive)
        timer = Thread(target=self.timeout)
        terminator.daemon = True
        listener.daemon = True
        self.running = True
        if self.listen():
            terminator.start()
            processor_in.start()
            processor_out.start()
            listener.start()
            timer.start()
            timer.join(0)
            listener.join(0)
            processor_in.join()
            processor_out.join()
            terminator.join(0)
            self.close_connection()
            self.close_socket()
            print "Stopping server"
            return True
        else:
            self.close_connection()
            self.close_socket()
            return False
