__author__ = 'Nicholas Rodofile'
from DNP3_Lib import *

ctrlCode = {
    "ACK": 0,
    "NACK": 1,
    "LINK_STATUS": 11,
    "NOT_SUPPORTED": 15
}

appFuncCode = {
    "CONFIRM": 0,
    "READ": 1,
    "WRITE": 2,
    "SELECT": 3,
    "OPERATE": 4,
    "DIRECT_OPERATE": 5,
    "DIRECT_OPERATE_NR": 6,
    "IMMED_FREEZE": 7,
    "IMMED_FREEZE_NR": 8,
    "FREEZE_CLEAR": 9,
    "FREEZE_CLEAR_NR": 10,
    "FREEZE_AT_TIME": 11,
    "FREEZE_AT_TIME_NR": 12,
    "COLD_RESTART": 13,
    "WARM_RESTART": 14,
    "INITIALIZE_DATA": 15,
    "INITIALIZE_APPL": 16,
    "START_APPL": 17,
    "STOP_APPL": 18,
    "SAVE_CONFIG": 19,
    "ENABLE_UNSOLICITED": 20,
    "DISABLE_UNSOLICITED": 21,
    "ASSIGN_CLASS": 22,
    "DELAY_MEASURE": 23,
    "RECORD_CURRENT_TIME": 24,
    "OPEN_FILE": 25,
    "CLOSE_FILE": 26,
    "DELETE_FILE": 27,
    "GET_FILE_INFO": 28,
    "AUTHENTICATE_FILE": 29,
    "ABORT_FILE": 30,
    "ACTIVATE_CONFIG": 31,
    "AUTHENTICATE_REQ": 32,
    "AUTH_REQ_NO_ACK": 33,
    "AUTHENTICATE_RESP": 131,
    "RESPONSE": 129,
    "UNSOLICITED_RESPONSE": 130,
}


def datetime_to_dnp3_spoof(date=None):
    if date is None:
        date = datetime.utcnow()
    seconds = (date - datetime(1970, 1, 1)).total_seconds()
    milliseconds = int(seconds * 1000)
    milliseconds += ((1000 * 60) * 60)
    return ''.join(chr((milliseconds >> (i*8)) & 0xff) for i in xrange(6))

def response_link_status(head):
    head.CONTROL.FUNC_CODE_SEC = appFuncCode["LINK_STATUS"]
    return


def select_response():
    #select operate
    #chunk 1 (d7c9810000)0c01280100000003016400(41b2)
    #chunk 2 00006400000000(005b)
    hex = "0c0128010000000301640041b200006400000000005b".decode("hex")
    return hex


def write_binary():
    binary_status = BinaryStatus()
    binindex = BinaryIndex(index=1)
    index_points = IndexPointsSingleOctetCountBinaryInput(count=1)
    class_objects_index = DNP3ClassObjectsIndex(Qualifier="one_octet_count", IndexPref=1)
    class_objects = DNP3ClassObjects(Obj=1, Var=2)
    data = class_objects/class_objects_index/index_points/binindex
    return data

def binary_counter_default_variation():
    class_objects_index = DNP3ClassObjectsIndex(Qualifier="no_range", IndexPref=0)
    class_objects = DNP3ClassObjects(Obj=20, Var=0)
    data = class_objects/class_objects_index
    return data

def write_IIN():
    binary_status = BinaryStatus(ONLINE=1, STATE=1)
    index_points = IndexPoints8BitAndStartStop(start=7, stop=7)
    class_objects_index = DNP3ClassObjectsIndex(Qualifier="one_octet_start_stop_index", IndexPref=0)
    class_objects = DNP3ClassObjects(Obj=80, Var=1)
    data = class_objects/class_objects_index/index_points/binary_status
    return data

def read_class_1():
    binary_status = BinaryStatus()
    index_points = IndexPoints8BitAndStartStop(start=1, stop=12)
    class_objects_index = DNP3ClassObjectsIndex(Qualifier="one_octet_start_stop_index")
    class_objects = DNP3ClassObjects(Obj=0, Var=0)
    data = class_objects/class_objects_index/index_points/binary_status
    return data


def read_request_class0123():
    class0 = DNP3ClassObjects(Obj=60, Var=02)/DNP3ClassObjectsIndex(Qualifier="no_range")
    class1 = DNP3ClassObjects(Obj=60, Var=03)/DNP3ClassObjectsIndex(Qualifier="no_range")
    class2 = DNP3ClassObjects(Obj=60, Var=04)/DNP3ClassObjectsIndex(Qualifier="no_range")
    class3 = DNP3ClassObjects(Obj=60, Var=01)/DNP3ClassObjectsIndex(Qualifier="no_range")
    data = class0/class1/class2/class3
    return data




def read_binary_response():
    #select operate
    #chunk 1 (d7c9810000)0c01280100000003016400(41b2)
    #chunk 2 00006400000000(005b)
    hex = "0a020000020101012e62".decode("hex")
    return hex

# def read_request_class0123():
#     #select operate
#     #chunk 1 (c0c001)3c02063c03063c04063c01068a51
#     hex = "3c02063c03063c04063c01068a51".decode("hex")
#     return hex

def write_data_objects():
    #(c2c102)500100070700(c5af)
    #hex = "500100070700".decode("hex")
    hex = "50010007070".decode("hex")
    return hex

def enable_spontaneous_msg():
    #(c4c314)3c02063c03063c0406(fdc9)
    hex = "3c02063c03063c0406".decode("hex")
    return hex

def control_response():
    #select operate
    #chunk 1 (d7c9810000)0c01280100000003016400(41b2)
    #chunk 2 00006400000000(005b)
    hex = "0c0128010000000301640041b200006400000000".decode("hex")
    return hex

def response_response():
    return

def read_request_process(msg):
    if msg.haslayer(DNP3RequestDataObjects):
        pass

def process_response_message(pkt):
    if pkt.haslayer(DNP3):
        if pkt.haslayer(DNP3ApplicationRequest):
            if pkt[DNP3ApplicationRequest].FUNC_CODE == appFuncCode["SELECT"]:
                #print "SELECT"
                return select_response()
            if pkt[DNP3ApplicationRequest].FUNC_CODE == appFuncCode["OPERATE"]:
                #print "OPERATE"
                return control_response()
            if pkt[DNP3ApplicationRequest].FUNC_CODE == appFuncCode["READ"]:
                #print "READ"
                return None


def read_request():
    hex = "3c02060000".decode("hex")
    return hex

def read_request_1():
    class1 = DNP3ClassObjects(Obj=60, Var=02)/DNP3ClassObjectsIndex(Qualifier="no_range")
    return class1

def read_request_2():
    class2 = DNP3ClassObjects(Obj=60, Var=03)/DNP3ClassObjectsIndex(Qualifier="no_range")
    return class2

def read_request_3():
    class3 = DNP3ClassObjects(Obj=60, Var=04)/DNP3ClassObjectsIndex(Qualifier="no_range")
    return class3

def time_request():
    hex = "0000".decode("hex")
    return hex

def write_time():
    timeanddate = datetime_to_dnp3_spoof()
    index_points = IndexPointsSingleOctetCountBinaryInput(count=1)
    class_objects_index = DNP3ClassObjectsIndex(Qualifier="one_octet_count", IndexPref=0)
    class_objects = DNP3ClassObjects(Obj=50, Var=3)
    data = class_objects/class_objects_index/index_points/timeanddate
    return data


def read_binary_request():
    hex = "3c02063c03063c04060a0006088b".decode("hex")
    return hex


def direct_operate_request():
    hex = "0c0128010002008101f401000025520000000000ffff".decode("hex")
    return hex


def select_read_request():
    selected = False
    while not selected:
        read_function = str(raw_input("Select a read function:\n>"))
        if read_function.isdigit():
            if read_function == "1":
                print "read_binary_request"
                return read_binary_request()
        else:
            print "read"
            return read_request()

def create_request_message(function):
    function_code = int(function)
    if function_code == appFuncCode["READ"]:
        #print "SELECT"
        return select_read_request()

    elif function_code == appFuncCode["DIRECT_OPERATE"]:
        print "direct_operate_request"
        return direct_operate_request()
    else:
        print "read_request"
        return read_request()


def create_request(msg):
    request = msg[1]
    if not request:
        return None

    if request == "Confirm":     #UNS response
        return None

    if request == "read_request_class0123":     #(Read Class 0, 1, 2, 3)
        return read_request_class0123()

    if request == "write_data_objects":
        return write_data_objects()

    if request == "enable_spontaneous_msg":
        return enable_spontaneous_msg()

    if request == "read_request":
        return read_request()

    if request == "read_requestClass1":
        return read_request_1()

    if request == "read_requestClass2":
        return read_request_2()

    if request == "read_requestClass3":
        return read_request_3()

    if request == "time_request":
        return time_request()

    if request == "write_time":
        return write_time()

    if request == "write_binary":
        return write_binary()

    if request == "write_IIN":
        return write_IIN()

    if request == "binary_counter_default_variation":
        return binary_counter_default_variation()