__author__ = 'Nicholas Rodofile'
from DNP3_Lib import *


class DNP3DataObjectHandler(object):
    def __init__(self):
        self.data_objects = {
            0: [],
            1: [],
            2: [],
            3: [],
            4: [],
        }
        self.data_objects_out = {
            0: [],
            1: [],
            2: [],
            3: [],
            4: [],
        }

    ''' Add data objects list'''
    def add_class_objects(self, data_objects):
        for d in data_objects:
            self.data_objects[d.Var].append(d)

    def clear_class_objects(self):
        self.data_objects = {
            0: [],
            1: [],
            2: [],
            3: [],
            4: [],
        }
        self.data_objects_out = {
            0: [],
            1: [],
            2: [],
            3: [],
            4: [],
        }

    ''' read data object'''
    def read_data_object(self, obj_class, index):
        data = self.data_objects[obj_class]
        binary_data_list = None
        for obj in data:
            if obj.haslayer(IndexPoints8BitAndStartStopBinaryInput):
                binary_data_list = obj[IndexPoints8BitAndStartStopBinaryInput].DataPointsBinaryInput
                break
        if binary_data_list is not None:
            if index < len(binary_data_list):
                if binary_data_list[index].haslayer(BinaryStatus):
                    index_points = IndexPoints8BitAndStartStopBinaryInput(start=index, stop=index,
                                                                          DataPointsBinaryInput=[binary_data_list[index]])
                    class_index = DNP3ClassObjectsIndex(Qualifier="one_octet_start_stop_index")
                    object_var = DNP3ClassObjects(Obj=1, Var=obj_class)
                    data_object = object_var/class_index/index_points
                    return data_object
        else:
            return ''

    '''
    Check if any requested class data has changed
    If class 0 is requested, send back all data objects
    '''
    def read_changed_data(self, request):
        if request.FUNC_CODE != 1:  # Read request
            return
        response_data = ''
        request_data = request.DataObject
        for req in request_data:
            if req.Var == 1:    # class 0
                return self.read_data(request)
        for req in request_data:
            data = self.data_objects_out[req.Var]
            self.data_objects_out[req.Var] = []
            for d in data:
                response_data = response_data/d
        return response_data

    '''
    Update counter objects if they exist
    '''
    def update_counter(self, index, value):
        obj_type = IndexPoints8BitAndStartStopCounter
        for req in range(len(self.data_objects)):
            data = self.data_objects[req]
            for obj in data:
                for points in obj:
                    if points.haslayer(obj_type) and \
                            points.haslayer(CounterStatus):
                        points[obj_type].DataPointsCounter[index].Counter = value
                        self.data_objects_out[points.Var] = points

    '''
    Update counter objects if they exist
    '''
    def update_counter_fuzz(self, index, value):
        obj_type = IndexPoints8BitAndStartStopCounter
        for req in range(len(self.data_objects)):
            data = self.data_objects[req]
            for obj in data:
                for points in obj:
                    if points.haslayer(obj_type) and \
                            points.haslayer(CounterStatus):
                        points[obj_type].DataPointsCounter[index].Counter = value

    '''
    Update binary input objects if they exist
    '''
    def update_binary_input_point(self, obj_class, index, value):
        data = self.data_objects[obj_class]
        binary_data_list = None
        for obj in data:
            if obj.haslayer(IndexPoints8BitAndStartStopBinaryInput):
                binary_data_list = obj[IndexPoints8BitAndStartStopBinaryInput].DataPointsBinaryInput
                break
        if binary_data_list is not None:
            if index < len(binary_data_list):
                if binary_data_list[index].haslayer(BinaryStatus):
                    binary_data_list[index] = BinaryStatus(struct.pack("<B", value))    # value to bits
                    index_points = IndexPoints8BitAndStartStopBinaryInput(start=index, stop=index,
                                                                          DataPointsBinaryInput=[binary_data_list[index]])
                    class_index = DNP3ClassObjectsIndex(Qualifier="one_octet_start_stop_index")
                    object_var = DNP3ClassObjects(Obj=1, Var=obj_class)
                    data_object = object_var/class_index/index_points
                    self.data_objects_out[obj_class] = data_object


    def update_binary_input_point_fuzz(self, obj_class, index, value):
        data = self.data_objects[obj_class]
        binary_data_list = None
        for obj in data:
            if obj.haslayer(IndexPoints8BitAndStartStopBinaryInput):
                binary_data_list = obj[IndexPoints8BitAndStartStopBinaryInput].DataPointsBinaryInput
                break
        if binary_data_list is not None:
            if index < len(binary_data_list):
                if binary_data_list[index].haslayer(BinaryStatus):
                    binary_data_list[index] = BinaryStatus(struct.pack("<B", value))    # value to bits

    '''
    get all data objects ans their point values
    '''
    def read_data(self, request):
        response_data = None
        request_data = request.DataObject
        for req in request_data:
            data = self.data_objects[req.Var]
            for d in data:
                if response_data is None:
                    response_data = d
                else:
                    response_data = response_data/d
        return response_data

#pcap = rdpcap("/root/scapyDNP3/DNP3_MITM_Lib/DNP3_Lib/pcaps/test_range2.pcap")
#p = pcap[10]
# r = pcap[9]
# #r.show()
# #p.show()
# a = p.DataObject
# #print a
# # count = len(a)
# # for d in a:
# #     print d.Var
# #hexdump(a)
#
#
#dataObjects = DNP3DataObjectHandler()
#dataObjects.add_class_objects(a)
# dataObjects.update_binary_input_point(2, 1, 23)
#
# # resp = dataObjects.get_changed_data(r)
# # if resp is not None:
# #     resp.show()
# # #dataObjects.get_changed_data(r)
# # dataObjects.update_counter(0, 10)
# # print "TEST"
# resp = dataObjects.get_changed_data(r)
# if resp is not None:
#     resp.show()
