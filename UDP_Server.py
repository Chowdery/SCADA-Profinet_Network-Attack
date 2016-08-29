__author__ = 'Nicholas Rodofile'
from MITM_Lib.Server import *

UDP_SERVER_STOP = False

class UDP_Server(Server):
    def __init__(self, node, port, timeout_time=(60 * 2)):
        Server.__init__(self, node, port, timeout_time)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def listen(self):
        try:
            self.socket.bind(('', self.port))
            #atexit.register(self.connection.close())
            return True
        except socket.error, exc:
            print "Server.listen Caught exception socket.error : %s" % exc
            self.running = False
            self.error = True
            return False

    def send(self, data):
        try:
            self.socket.sendto(data[0], data[1])
        except socket.error, exc:
            print "Server.send Caught exception socket.error : %s" % exc
            self.running = False
            self.socket.close()

    def timeout(self):
        while not self.running:
            pass
        if self.timeout_time > 0:
            sleep(self.timeout_time)
            if self.running:
                print "- Time Up ..."
                self.running = False
                sleep(10)

    def process_out(self):

        while self.running:
            if not self.queue_in.empty():
                data_in = self.queue_in.get()
                if data_in is not None:
                    self.send(["\xFF\xFF\xFF\xFF", data_in[1]])
            else:
                pass

    def quit(self):
        global UDP_SERVER_STOP
        while self.running:
            if UDP_SERVER_STOP:
                self.running = False
                print "UDP stop"

    def receive(self):
        try:
            while self.running:
                data = self.socket.recvfrom(self.size)
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

if __name__ == "__main__":
    n = Node()
    udp = UDP_Server(n, 23, 0)
    udp_mask = Thread(target=udp.start)
    udp_mask.start()
    sleep(15)
    print "STOP"
    UDP_SERVER_STOP = True