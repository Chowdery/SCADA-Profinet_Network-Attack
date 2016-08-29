__author__ = 'Nicholas Rodofile'

from DNP3_Lib_ import *

pcap = rdpcap("/root/scapyDNP3/DNP3_MITM_Lib/DNP3_Lib/pcaps/test_range2.pcap")

#pkts = rdpcap("/media/sf_Development/DNP3_Lib/dnp3_read.pcap")
#pkts1 = rdpcap("/media/sf_Development/DNP3_Lib/dnp3_request_link_status.pcap")
#pkts2 = rdpcap("/media/sf_Development/DNP3_Lib/dnp3_select_operate.pcap")
#pkts3 = rdpcap("/media/sf_Development/DNP3_Lib/dnp3_write.pcap")
#pkts4 = rdpcap("/media/sf_Development/DNP3_Lib/DNP3ReadRequest.pcap")
#pkts5 = rdpcap("/media/sf_Development/DNP3_Lib/DNP3SelectOperateRequest.pcap")
#pkts6 = rdpcap("/media/sf_Development/DNP3_Lib/DNP3SelectOperateRequest.pcap")

#pkts[3].show2()
#pkts1[3].show2()
#pkts2[3].show2()

#print pkts2[7].summary()

#select_dnp3 = pkts2[3]
#operate_dnp3 = pkts2[7]

#a[3].show2()

#a.LENGTH = None

#a[1].FIN = 0
#a[3].show2()
#hexdump(pkts2[7][6][1])
#print "ad chunk"
#a[3].update_data_chunks('\xc2\x04\x0c\x01\x01\x00\x01\x00\x03\x01\x00\x00\x00\x00\x00\x03')
#a[3].update_data_chunks('\xc2\x04\x0c\x01\x01\x00\x01\x00\x03\x01\x00\x00\x00\x00\x00\x03')
#a[3].update_data_chunks('\xc2\x04\x0c\x01\x01\x00\x01\x00\x03\x01\x00\x00\x00\x00\x00\x03')
#a[3].update_data_chunks('\xc2\x04\x0c\x01\x01\x00\x01\x00\x03\x01\x00\x00\x00\x88\x00\x03')
#a[3].update_data_chunks('\xc2\x04\x0c\x01\x01\x00\x01\x00\x03\x01\x00\x00\x00\x00\x00\x03')
#a[3].update_data_chunks('\xc2\x04\x0c\x01\x01\x00\x01\x00\x03\x01\x88\x00\x00\x00\x00\x03')
#a[3].update_data_chunks('\xc2\x04\x0c\x01\x01\x00\x01\x00\x03\x01\x00\x00\x00\x00\x00\x03')

#print a[3].data_chunks_updated
#select_dnp3[3].show2()
#a[3].remove_data_chunk(2)
#a[3].show2()
#a[3].use_default_payload()
#a[3].show2()



#print hex(crcDNP("\xc1\xc2\x04\x0c\x01\x28\x01\x00\x01\x00\x03\x01\x64\x00\x00\x00"))
#print hex(crcDNP("\x64\x00\x00\x00\x00"))


#pkts3[3].show2()
#pkts4[5].show2()
#pkts5[3].show2()

#a[3][2].FIN = "unset"
#a[3][2] = None

a = DNP3(DESTINATION=65535, SOURCE=65535, CONTROL=DNP3HeaderControl(PRM=MASTER, DIR=OUTSTATION, FCB=SET))/\
    DNP3Transport(FIN=SET, FIR=SET, SEQUENCE=100)/DNP3ApplicationResponse(FUNC_CODE="RESPONSE")
#a.show()
#a.show2()

bs = BinaryStatus()
data = bs/bs/bs/bs/bs/bs/bs/bs/bs/bs/bs/bs

dnp3Res = IndexPoints8BitAndStartStop(start=1, stop=12)
ind = DNP3ClassObjectsIndex(Qualifier="one_octet_start_stop_index")
b = DNP3ClassObjects(Obj=1, Var=2)
dnpdata = b/ind/dnp3Res/data
dnp = a/dnpdata/dnpdata
#p = Ether()/IP()/TCP(sport=dnp3_port, dport=dnp3_port, flags="PA")/dnp
#p.show()
#sendp(p)
#a.show2()

p = pcap[9]
#p.show()
a = p[DNP3RequestDataObjects].DataObject
count = len(a)
for d in a:
    print d.Var
#hexdump(a)


# pkts = rdpcap("/root/scapyDNP3/DNP3_MITM_Lib/DNP3_Lib/pcaps/test_range4.pcap")
# #for p in pkts:
#  #   if p.haslayer(DNP3ApplicationRequest):
# #    sendp(p)
# #pkts[10].show2()
# #print pkts[10].summary()
# index = 6
# pkt = '\x05\x64\x08\xc4\x01\x00\x00\x00\xdc\x16\xe3\xd2\x00\xbd\x98\x05\x64\x08\xc4\x01\x00\x00\x00\xdc\x16\xe3\xd2\x00\xbd\x98\x05\x64\x08\xc4\x01\x00\x00\x00\xdc\x16\xe3\xd2\x00\xbd\x98'
# print pkts[index][DNP3].LENGTH
# print dnp3_calc_len_crc(pkts[index][DNP3].LENGTH)
# print dnp3_calc_len(pkts[index][DNP3])
# a = split_dnp3_layer(pkt)
# c = 0
# for p in a:
#     print c
#     ls(p)
#     c += 1
#
# #pkt = str(pkts[index][DNP3])
# #print [pkt[15:30]]
# #dnp = DNP3(pkt[15:30])
# #dnp.show()


