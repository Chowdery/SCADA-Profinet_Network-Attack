# Copyright 2015-2016 Nicholas Rodofile <n.rodofile@qut.edu.au>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser Public License for more details.
#
# You should have received a copy of the GNU Lesser Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

 
__author__ = 'Nicholas Rodofile'
from scapy.all import *
import crcmod.predefined
from datetime import datetime

bitState = {1: "SET", 0: "UNSET"}
stations = {1: "MASTER", 0: "OUTSTATION"}
chunk_len = 18 #DNP3 data chunk inc crc
data_chunk_len = 16 #DNP3 data chunk
dnp3_data_link_len = 10 #including CRC

MASTER = 1
OUTSTATION = 0
SET = 1
UNSET = 0
dnp3_port = 20000

Transport_summary = "Seq:%DNP3Transport.SEQUENCE% "
Application_Rsp_summary = "%DNP3ApplicationResponse.FUNC_CODE% "
Application_Req_summary = "%DNP3ApplicationRequest.FUNC_CODE% "
DNP3_summary = "From %DNP3.SOURCE% to %DNP3.DESTINATION% "

'''
Initalise a predefined crc object for DNP3 Cyclic Redundancy Check
Info : http://crcmod.sourceforge.net/crcmod.predefined.html
'''
def crcDNP(data):
    crc16DNP = crcmod.predefined.mkCrcFun('crc-16-dnp')
    return crc16DNP(data)


def CRC_check(chunk, crc):
    chunk_crc = crcDNP(chunk)
    crc = struct.unpack('<H', crc)[0]
    if crc == chunk_crc:
        return True, crc
    else:
        return False, crc


def update_data_chunk_crc(chunk):
    crc = crcDNP(chunk[:-2])
    chunk = chunk[:-2] + struct.pack('<H', crc)
    return chunk

def crc_octet(chunk):
    crc = crcDNP(chunk)
    return struct.pack('<H', crc)

def add_data_chunk_crc(chunk):
    crc = crcDNP(chunk)
    crc_chunk = chunk + struct.pack('<H', crc)
    return crc_chunk


def add_CRC_payload(payload):
    if len(payload) > 18:
        chunk = payload[:18]
        chunk = update_data_chunk_crc(chunk)
        payload = chunk + payload[18:]

    else:
        chunk = payload[:-2]
        chunk = update_data_chunk_crc(chunk)
        payload = chunk
    return payload

def remove_dnp3_crc(s):
    pay_len = len(s)
    chunks = pay_len / chunk_len  # chunk size
    last_chunk = pay_len % chunk_len
    if last_chunk > 0:
            chunks += 1
    data_chunks = []
    for c in range(chunks):
        index = c * chunk_len
        if pay_len < (chunk_len + index):
            data_chunks.append(s[index:])
        else:
            data_chunks.append(s[index:index+chunk_len])
    data = ''
    for d in data_chunks:
        data = data + d[:-2]
    return data


def add_dnp3_crc(s):
    """DEV: is called right after the current layer has been dissected"""
    pay_len = len(s)
    chunks = pay_len / data_chunk_len  # chunk size
    last_chunk = pay_len % data_chunk_len
    if last_chunk > 0:
            chunks += 1
    data_chunks = []
    for c in range(chunks):
        index = c * data_chunk_len
        if pay_len < (data_chunk_len + index):
            data_chunks.append(s[index:])
        else:
            data_chunks.append(s[index:index+data_chunk_len])
    data = ''
    for d in data_chunks:
        crc = crc_octet(d)
        data = data + d + crc
    return data

objectGroup = {
    1: "binary_input",
    2: "binary_input_no_time_change",
    7: "time_and_date",
    20: "counter"
}

qualifierCode = {
    0: "one_octet_start_stop_index",
    1: "two_octet_start_stop_index",
    2: "four_octet_start_stop_index",
    3: "one_octet_start_stop_virt_add",
    4: "two_octet_start_stop_virt_add",
    5: "four_octet_start_stop_virt_add",
    6: "no_range",
    7: "one_octet_count",
    8: "two_octet_count",
    9: "four_octet_count"
}

applicationFunctionCode = {
    0: "CONFIRM",
    1: "READ",
    2: "WRITE",
    3: "SELECT",
    4: "OPERATE",
    5: "DIRECT_OPERATE",
    6: "DIRECT_OPERATE_NR",
    7: "IMMED_FREEZE",
    8: "IMMED_FREEZE_NR",
    9: "FREEZE_CLEAR",
    10: "FREEZE_CLEAR_NR",
    11: "FREEZE_AT_TIME",
    12: "FREEZE_AT_TIME_NR",
    13: "COLD_RESTART",
    14: "WARM_RESTART",
    15: "INITIALIZE_DATA",
    16: "INITIALIZE_APPL",
    17: "START_APPL",
    18: "STOP_APPL",
    19: "SAVE_CONFIG",
    20: "ENABLE_UNSOLICITED",
    21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS",
    23: "DELAY_MEASURE",
    24: "RECORD_CURRENT_TIME",
    25: "OPEN_FILE",
    26: "CLOSE_FILE",
    27: "DELETE_FILE",
    28: "GET_FILE_INFO",
    29: "AUTHENTICATE_FILE",
    30: "ABORT_FILE",
    31: "ACTIVATE_CONFIG",
    32: "AUTHENTICATE_REQ",
    33: "AUTH_REQ_NO_ACK",
    129: "RESPONSE",
    130: "UNSOLICITED_RESPONSE",
    131: "AUTHENTICATE_RESP",
}


class BinaryStatus(Packet):
    name = "BinaryStatus"
    fields_desc = [
        BitEnumField("STATE", UNSET, 1, bitState),
        BitEnumField("Reserved", UNSET, 1, bitState),
        BitEnumField("CHATTER_FILTER", UNSET, 1, bitState),
        BitEnumField("LOCAL_FORCED", UNSET, 1, bitState),
        BitEnumField("REMOTE_FORCED", UNSET, 1, bitState),
        BitEnumField("COMM_LOST", UNSET, 1, bitState),
        BitEnumField("RESTART", UNSET, 1, bitState),
        BitEnumField("ONLINE", UNSET, 1, bitState),
    ]

    def extract_padding(self, p):
        return "", p


class TimeAndDate(Packet):
    name = "TimeAndDate"
    fields_desc = [
        UTCTimeField("time", 0),
    ]

    def extract_padding(self, p):
        return "", p


class BinaryIndex(Packet):
    name = "BinaryIndex"
    fields_desc = [
        ByteField("index", None),
        PacketField("binary_status", BinaryStatus(), BinaryStatus)
    ]

    def extract_padding(self, p):
        return "", p


class CounterStatus(Packet):
    name = "CounterStatus"
    fields_desc = [
        BitEnumField("ONLINE", UNSET, 1, bitState),
        BitEnumField("RESTART", UNSET, 1, bitState),
        BitEnumField("COMM_LOST", UNSET, 1, bitState),
        BitEnumField("REMOTE_FORCED", UNSET, 1, bitState),
        BitEnumField("LOCAL_FORCED", UNSET, 1, bitState),
        BitEnumField("CHATTER_FILTER", UNSET, 1, bitState),
        BitEnumField("Reserved", UNSET, 1, bitState),
        BitEnumField("STATE", UNSET, 1, bitState),
        LEShortField("Counter", None),
    ]

    def extract_padding(self, p):
        return "", p


def get_range_from_index(start, stop):
    if start == stop:
        return 1 #The index is the same, therefore 1 index point
    count = 0
    if start == 0: #need to include index 0 as a point
        count += 1
    index_range = stop - start
    count += index_range
    return count


class IndexPoints8BitAndStartStop(Packet):
    fields_desc = [
        ByteField("start", None),
        ByteField("stop", None),
    ]

    def extract_padding(self, p):
        return "", p


class IndexPoints8BitAndStartStopBinaryInput(IndexPoints8BitAndStartStop):
    fields_desc = [
        ByteField("start", None),
        ByteField("stop", None),
        PacketListField("DataPointsBinaryInput", None, BinaryStatus,
                        count_from=lambda pkt: get_range_from_index(pkt.start, pkt.stop))
    ]


class IndexPoints8BitAndStartStopCounter(IndexPoints8BitAndStartStop):
    fields_desc = [
        ByteField("start", None),
        ByteField("stop", None),
        PacketListField("DataPointsCounter", None, CounterStatus,
                        count_from=lambda pkt: get_range_from_index(pkt.start, pkt.stop))
    ]


class IndexPointsSingleOctetCountBinaryInput(IndexPoints8BitAndStartStop):
    fields_desc = [
        ByteField("count", None),
        PacketListField("DataPointsBinary", None, BinaryIndex,
                        count_from=lambda pkt:pkt.count)
    ]

    def extract_padding(self, p):
        return "", p


class DNP3ClassObjectsIndex(Packet):
    fields_desc = [
        BitField("reserved", UNSET, 1),
        BitField("IndexPref", UNSET, 3),
        BitEnumField("Qualifier", UNSET, 4, qualifierCode)
    ]

    def extract_padding(self, p):
        return "", p


class DNP3ResponseClassObjectsBinaryInput(DNP3ClassObjectsIndex):
    fields_desc = [
        BitField("reserved", UNSET, 1),
        BitField("IndexPref", UNSET, 3),
        BitEnumField("Qualifier", UNSET, 4, qualifierCode),
        ConditionalField(PacketField("8BitAndStartStopBinary", IndexPoints8BitAndStartStopBinaryInput(),
                                     IndexPoints8BitAndStartStopBinaryInput),
                         lambda x:x.Qualifier == 0),
        ConditionalField(PacketField("SingleOctetCount", IndexPointsSingleOctetCountBinaryInput(),
                                     IndexPointsSingleOctetCountBinaryInput),
                         lambda x:x.Qualifier == 7),
    ]


class DNP3ResponseClassObjectsCounter(DNP3ClassObjectsIndex):
    fields_desc = [
        BitField("reserved", UNSET, 1),
        BitField("IndexPref", UNSET, 3),
        BitEnumField("Qualifier", UNSET, 4, qualifierCode),
        PacketField("index", IndexPoints8BitAndStartStopCounter(),
                    IndexPoints8BitAndStartStopCounter)
    ]


class DNP3RequestClassObjectsIndex(DNP3ClassObjectsIndex):
    pass


class DNP3ResponseClassObjects(Packet):
    fields_desc = [
        ByteEnumField("Obj", None, objectGroup),
        ByteField("Var", None),
        ConditionalField(PacketField("binary_input", DNP3ResponseClassObjectsBinaryInput(),
                                     DNP3ResponseClassObjectsBinaryInput),
                         lambda x:x.Obj == 1),
        ConditionalField(PacketField("binary_input_no_time_change", DNP3ResponseClassObjectsBinaryInput(),
                                     DNP3ResponseClassObjectsBinaryInput),
                         lambda x:x.Obj == 2),
        ConditionalField(PacketField("counter", DNP3ResponseClassObjectsCounter(),
                                     DNP3ResponseClassObjectsCounter),
                         lambda x:x.Obj == 20),

    ]

    def extract_padding(self, p):
        return "", p


class DNP3ClassObjects(Packet):
    fields_desc = [
        ByteField("Obj", None),
        ByteField("Var", None)
    ]

    def extract_padding(self, p):
        return "", p


class DNP3RequestClassObjects(Packet):
    fields_desc = [
        ByteField("Obj", None),
        ByteField("Var", None),
        PacketField("index", DNP3RequestClassObjectsIndex(), DNP3RequestClassObjectsIndex)
    ]

    def extract_padding(self, p):
        return "", p


class DNP3ResponseDataObjects(DNP3ClassObjects):
    fields_desc = [
        PacketListField("DataObject",
                        DNP3ResponseClassObjects(),
                        DNP3ResponseClassObjects)
    ]

    def guess_payload_class(self, payload):
        return Packet.guess_payload_class(self, payload)


class DNP3RequestDataObjects(DNP3ClassObjects):
    fields_desc = [
        PacketListField("DataObject",
                        DNP3RequestClassObjects(),
                        DNP3RequestClassObjects)
    ]

    def guess_payload_class(self, payload):
        return Packet.guess_payload_class(self, payload)


class DNP3Application(Packet):
    def guess_payload_class(self, payload):
        return Packet.guess_payload_class(self, payload)


class DNP3ApplicationControl(Packet):
    fields_desc = [
        BitEnumField("FIN", SET, 1, bitState),
        BitEnumField("FIR", SET, 1, bitState),
        BitEnumField("CON", SET, 1, bitState),
        BitEnumField("UNS", SET, 1, bitState),
        BitField("SEQ", UNSET, 4),
    ]

    def extract_padding(self, p):
        return "", p


class DNP3ApplicationIIN(Packet):
    name = "DNP3_Application_response"
    fields_desc = [
        BitEnumField("DEVICE_RESTART", UNSET, 1, bitState),
        BitEnumField("DEVICE_TROUBLE", UNSET, 1, bitState),
        BitEnumField("LOCAL_CONTROL", UNSET, 1, bitState),
        BitEnumField("NEED_TIME", UNSET, 1, bitState),
        BitEnumField("CLASS_3_EVENTS", UNSET, 1, bitState),
        BitEnumField("CLASS_2_EVENTS", UNSET, 1, bitState),
        BitEnumField("CLASS_1_EVENTS", UNSET, 1, bitState),
        BitEnumField("BROADCAST", UNSET, 1, bitState),
        BitEnumField("RESERVED_1", UNSET, 1, bitState),
        BitEnumField("RESERVED_2", UNSET, 1, bitState),
        BitEnumField("CONFIG_CORRUPT", UNSET, 1, bitState),
        BitEnumField("ALREADY_EXECUTING", UNSET, 1, bitState),
        BitEnumField("EVENT_BUFFER_OVERFLOW", UNSET, 1, bitState),
        BitEnumField("PARAMETER_ERROR", UNSET, 1, bitState),
        BitEnumField("OBJECT_UNKNOWN", UNSET, 1, bitState),
        BitEnumField("NO_FUNC_CODE_SUPPORT", UNSET, 1, bitState),
    ]

    def extract_padding(self, p):
        return "", p


class DNP3ApplicationResponse(DNP3Application):
    name = "DNP3_Application_response"
    fields_desc = [
        PacketField("Application_control", DNP3ApplicationControl(), DNP3ApplicationControl),
        BitEnumField("FUNC_CODE", 1, 8, applicationFunctionCode),
        PacketField("IIN", DNP3ApplicationIIN(), DNP3ApplicationIIN),
    ]

    def mysummary(self):
        if isinstance(self.underlayer.underlayer, DNP3):
            return self.underlayer.underlayer.sprintf(DNP3_summary + Transport_summary + Application_Rsp_summary)
        if isinstance(self.underlayer, DNP3Transport):
            return self.underlayer.sprintf(Transport_summary + Application_Rsp_summary)
        else:
            return self.sprintf(Application_Req_summary)

    def guess_payload_class(self, payload):
        #code = applicationFunctionCode[self.FUNC_CODE]
        if len(payload) > 0:
            #if code == "RESPONSE" or code == "UNSOLICITED_RESPONSE":
            return DNP3ResponseDataObjects
        return Packet.guess_payload_class(self, payload)


class DNP3ApplicationRequest(DNP3Application):
    name = "DNP3_Application_request"
    fields_desc = [
        PacketField("Application_control", DNP3ApplicationControl(), DNP3ApplicationControl),
        BitEnumField("FUNC_CODE", 1, 8, applicationFunctionCode),
    ]

    def mysummary(self):
        if isinstance(self.underlayer.underlayer, DNP3):
            return self.underlayer.underlayer.sprintf(DNP3_summary + Transport_summary + Application_Req_summary)
        if isinstance(self.underlayer, DNP3Transport):
            return self.underlayer.sprintf(Transport_summary + Application_Req_summary)
        else:
            return self.sprintf(Application_Req_summary)

    def guess_payload_class(self, payload):
        #if applicationFunctionCode[self.FUNC_CODE] == "READ":
        if len(payload) > 0:
            return DNP3RequestDataObjects

        return Packet.guess_payload_class(self, payload)


class DNP3Transport(Packet):
    name = "DNP3_Transport"
    fields_desc = [
        BitEnumField("FIN", None, 1, bitState),
        BitEnumField("FIR", None, 1, bitState),
        BitField("SEQUENCE", 0, 6),
    ]

    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, DNP3):
            DIR = self.underlayer.CONTROL.DIR
            if DIR == MASTER:
                return DNP3ApplicationRequest
            if DIR == OUTSTATION:
                return DNP3ApplicationResponse
        else:
            return Packet.guess_payload_class(self, payload)


class DNP3HeaderControl(Packet):
    name = "DNP3_Header_control"

    controlFunctionCodePri = {
        0: "RESET_LINK_STATES",
        2: "TEST_LINK_STATES",
        3: "CONFIRMED_USER_DATA",
        4: "UNCONFIRMED_USER_DATA",
        9: "REQUEST_LINK_STATUS",
    }

    controlFunctionCodeSec = {
        0: "ACK",
        1: "NACK",
        11: "LINK_STATUS",
        15: "NOT_SUPPORTED",
    }

    cond_field = [
        BitEnumField("FCB", 0, 1, bitState),
        BitEnumField("FCV", 0, 1, bitState),
        BitEnumField("FUNC_CODE_PRI", 4, 4,  controlFunctionCodePri),
        BitEnumField("reserved", 0, 1, bitState),
        BitEnumField("DFC", 0, 1, bitState),
        BitEnumField("FUNC_CODE_SEC", 4, 4,  controlFunctionCodeSec),
    ]

    fields_desc = [
        BitEnumField("DIR", MASTER, 1, stations),  # 9.2.4.1.3.1 DIR bit field
        BitEnumField("PRM", MASTER, 1,  stations),  # 9.2.4.1.3.2 PRM bit field
        ConditionalField(cond_field[0], lambda x:x.PRM == MASTER),
        ConditionalField(cond_field[1], lambda x:x.PRM == MASTER),
        ConditionalField(cond_field[2], lambda x:x.PRM == MASTER),
        ConditionalField(cond_field[3], lambda x:x.PRM == OUTSTATION),
        ConditionalField(cond_field[4], lambda x:x.PRM == OUTSTATION),
        ConditionalField(cond_field[5], lambda x:x.PRM == OUTSTATION),
    ]

    def extract_padding(self, p):
        return "", p


class DNP3(Packet):
    name = "DNP3"
    fields_desc = [
        XShortField("START", 0x0564),
        ByteField("LENGTH", None),
        PacketField("CONTROL", None, DNP3HeaderControl),
        LEShortField("DESTINATION", None),
        LEShortField("SOURCE", None),
        XShortField("CRC", None),
    ]

    def pre_dissect(self, s):
        s = s[:dnp3_data_link_len] + remove_dnp3_crc(s[dnp3_data_link_len:])
        return s

    def post_build(self, pkt, pay):
        pay_len = len(pay)
        chunks = pay_len / chunk_len  # chunk size
        last_chunk = pay_len % chunk_len

        if last_chunk > 0:
                chunks += 1

        #Add CRCs to data chunks
        pay = add_dnp3_crc(pay)
        if self.LENGTH is None:
            # Remove length , crc, start octets as part of length
            length = (len(pkt+pay) - ((chunks * 2) + 1 + 2 + 2))
            pkt = pkt[:2] + struct.pack('<B', length) + pkt[3:]
        CRC = crcDNP(pkt[:8])  # use only the first 8 octets
        if self.CRC is None:
            # Update data-link CRC
            pkt = pkt[:-2] + struct.pack('H', CRC)
        else:
            if CRC != self.CRC:
                pkt = pkt[:-2] + struct.pack('H', CRC)
        #Add all CRCs in payload
        return pkt+pay

    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return DNP3Transport
        else:
            return Packet.guess_payload_class(self, payload)

bind_layers(TCP, DNP3, dport=dnp3_port)
bind_layers(TCP, DNP3, sport=dnp3_port)
bind_layers(UDP, DNP3, dport=dnp3_port)
bind_layers(UDP, DNP3, sport=dnp3_port)

def dnp3_calc_len_crc(dnp3_length):
    #add length , crc, start octets as part of total length
    total_len = (dnp3_length + 1 + 2 + 2)
    application_data = (total_len - dnp3_data_link_len)
    chunks = (application_data / data_chunk_len)
    last_chunk = (application_data % chunk_len)

    if last_chunk > 0:
        chunks += 1
    # add crc checks in
    real_len = (application_data + (chunks * 2))
    return real_len + dnp3_data_link_len

def dnp3_calc_len(p):
    length = len(p)
    application_data = (length - dnp3_data_link_len)
    chunks = (application_data / chunk_len)  # chunk size
    last_chunk = (application_data % chunk_len)
    if last_chunk > 0:
        chunks += 1
    # Remove length , crc, start octets as part of length
    dnp3_len = (len(p) - ((chunks * 2) + 1 + 2 + 2))
    return dnp3_len


#   Can only be used in real time, not from pcaps
def split_dnp3_layer(p):
    dnp3_layers = []
    packet = copy.deepcopy(p)
    dnp3 = DNP3(p)
    if dnp3.START == 0x0564:
        length = dnp3_calc_len(p)
        if dnp3.LENGTH != length:
            real_length = dnp3_calc_len_crc(dnp3.LENGTH)
            dnp3_layers.append(DNP3(p[:real_length]))
            dnp3_layers = dnp3_layers + split_dnp3_layer(packet[real_length:])
        else:
            dnp3_layers.append(dnp3)
    return dnp3_layers

def dnp3_to_datetime(octets):
    milliseconds = 0
    for i, value in enumerate(octets):
        milliseconds = milliseconds | (ord(value) << (i*8))

    date = datetime.utcfromtimestamp(milliseconds/1000.)
    return date.strftime('%b %d, %Y %H:%M:%S.%f UTC')

def datetime_to_dnp3(date=None):
    if date is None:
        date = datetime.utcnow()
    seconds = (date - datetime(1970, 1, 1)).total_seconds()
    milliseconds = int(seconds * 1000)
    return ''.join(chr((milliseconds >> (i*8)) & 0xff) for i in xrange(6))

def datetime_dnp3_to_int(date=None):
    if date is None:
        date = datetime.utcnow()
    seconds = (date - datetime(1970, 1, 1)).total_seconds()
    return int(seconds * 1000)


if __name__ == '__main__':
    class_objects_index = DNP3ClassObjectsIndex(Qualifier="no_range", IndexPref=0)
    class_objects = DNP3ClassObjects(Obj=20, Var=0)
    data = class_objects/class_objects_index



    a = DNP3(DESTINATION=65535, SOURCE=65535, CONTROL=DNP3HeaderControl(PRM=MASTER, DIR=OUTSTATION, FCB=SET))/\
    DNP3Transport(FIN=SET, FIR=SET, SEQUENCE=100)/DNP3ApplicationRequest(FUNC_CODE="IMMED_FREEZE")

    dnp = a/data
    # send(IP(dst="192.168.10.222")/TCP(sport=dnp3_port, dport=dnp3_port, flags="PA")/dnp)
    dnp[DNP3].SEQUENCE = 0

    dnp3_pcap = rdpcap("/root/DNP3_MITM_Lib 2/DNP3_MITM_Lib/DNP3_Lib/pcaps/bin_stat.pcap")
    pkt = dnp3_pcap[0]
    pkt.show()
    sendp(pkt)
