import pcapy
import time
import warnings
import socket
from struct import *
import os
import iptc
import json
import argparse

warnings.filterwarnings("ignore", category=DeprecationWarning)

def get_bytes(t, iface='eth0'):
    with open('/sys/class/net/' + iface + '/statistics/' + t + '_bytes', 'r') as f:
        data = f.read();
        return int(data)

def decode_ip_packet(packet):
    # Parse the Ethernet header (14 bytes)
    source_port = -1
    dest_port = -1
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # Parse the IP header (20 bytes)
    ip_header = packet[eth_length:20+eth_length]
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    # Parse the TCP or UDP header (20 bytes)
    if protocol == 6:
        tcp_header = packet[iph_length + eth_length:iph_length + eth_length + 20]
        tcph = unpack('!HHLLBBHHH', tcp_header)
        source_port = tcph[0]
        dest_port = tcph[1]
    elif protocol == 17:
        udp_header = packet[iph_length + eth_length:iph_length + eth_length + 8]
        udph = unpack('!HHHH', udp_header)
        source_port = udph[0]
        dest_port = udph[1]

    return (s_addr, d_addr, source_port, dest_port)
 # Parse the TCP or UDP header (20 bytes)
    if protocol == 6:
        tcp_header = packet[iph_length+eth_length:iph_length+eth_length+20]
        tcph = unpack('!HHLLBBHHH', tcp_header)
        source_port = tcph[0]
        dest_port = tcph[1]
    elif protocol == 17:
        udp_header = packet[iph_length+eth_length:iph_length+eth_length+8]
        udph = unpack('!HHHH', udp_header)
        source_port = udph[0]
        dest_port = udph[1]


    return (s_addr, d_addr, source_port, dest_port)
# Open the network interface for packet capture
cap = pcapy.open_live("eth0", 65536, True, 0)
blacklist = []

def save_blacklist(blacklist_file):
    listobj = []
    for item in blacklist:
        item_json = {
            "port" : item[0],
            "time" : item[1]
        }
        listobj.append(item_json)
    with open (blacklist_file, 'w') as json_file:
        json.dump(listobj, json_file, indent=4, separators=(',',': '))
    json_file.close()

def load_blacklist(blacklist_file):
    listobj = []
    if not os.path.isfile(blacklist_file):
        with open(blacklist_file, "w") as file:
            pass
        return 0;

    with open(blacklist_file) as json_file:
        listobj = json.load(json_file)

    for item in listobj:
        rule = iptc.Rule()
        rule.in_interface = "eth0"
        rule.protocol = "udp"
        rule.target = iptc.Target(rule, "DROP")
        match = rule.create_match("udp")
        match.sport = str(item["port"])
        match.dport = "123"
        rule.add_match(match)
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.insert_rule(rule)
        blacklist_tmp = (item["port"], item["time"])
        blacklist.append(blacklist_tmp)

blacklist_file = "/etc/blacklist.json"
timeout_arg = 180

def load_config(config_file):
    global blacklist_file
    global timeout_arg
    with open(config_file) as json_file:
        item = json.load(json_file)
        blacklist_file = item["blacklist"]
        timeout_arg = item["timeout"]

# Initialize packet and time counters
# Capture packets for 10 seconds
parser = argparse.ArgumentParser()
parser.add_argument("-b", "--blacklist", help="Blacklist File")
parser.add_argument("-t", "--timeout", help="Timeout")
parser.add_argument("-c", "--config", help="Config File")
args = parser.parse_args()
if(args.blacklist is not None):
    blacklist_file = args.blacklist
if(args.timeout is not None):
    timeout_arg = args.timeout
if(args.config is not None):
    config_file = args.config
    load_config(config_file)

#if __name__ == '__main__':
#    load_blacklist(blacklist_file)

logfile = open('/var/log/portfilter.log', 'w')
logfile.write("TIMEOUT: " + str(timeout_arg) + "\n")
logfile.close()
init_data = get_bytes('tx')/1024/1024
init_time = time.time()
while True:
    pkt_count = 0
    start_time = time.time()
    source_port_count = []
    for i in range (0,65535):
        source_port_count.append(0)
    #check_timeout

    while (time.time() - start_time) < 2:
        if((time.time() - init_time) % 10 < 0.1):
            #save_blacklist(blacklist_file)
            if(len(blacklist) > 0):
                for i in range(0, len(blacklist)):
                    if(i >= len(blacklist)):
                        break
                    if (int(time.time() - blacklist[i][1]) > timeout_arg):
                        try:
                            logfile = open('/var/log/portfilter.log', 'a')
                            logfile.write(
                                str(time.time() - init_time) + " TRYING TO REMOVE " + str(blacklist[i][0]) +" ,FIREWALL SIZE="+ str(len(blacklist))+ " ,LOAD AVERAGE="+str(os.getloadavg()[0]) + " ,DATA SENT="+ str((get_bytes('tx')/1024/1024 - init_data)*8)+ " Mbps" +"\n")
                            logfile.close()
                            rule.in_interface = "eth0"
                            rule.protocol = "udp"
                            rule.target = iptc.Target(rule, "DROP")
                            match = rule.create_match("udp")
                            match.sport = str(blacklist[i][0])
                            match.dport = "123"
                            rule.add_match(match)
                            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
                            chain.delete_rule(rule)
                            logfile = open('/var/log/portfilter.log', 'a')
                            logfile.write(str(time.time() - init_time) + " DELTED " + str(blacklist[i][0]) +" ,FIREWALL SIZE="+ str(len(blacklist))+ " ,LOAD AVERAGE="+str(os.getloadavg()[0]) + " ,DATA SENT="+ str((get_bytes('tx')/1024/1024 - init_data)*8)+ " Mbps" "\n")
                            logfile.close()
                            blacklist.pop(i)
 #                           save_blacklist(blacklist_file)
                        except:
                            break

        # Read a packet from the network interface
        (header, packet) = cap.next()
        (s_addr, d_addr, source_port, dest_port) = decode_ip_packet(packet)
        if (source_port == 123):
            source_port_count[dest_port] = source_port_count[dest_port]+1

    for i in range (1,65535):
        #Suspected Attack Detected
        if(source_port_count[i] > 8):
            rule = iptc.Rule()
            rule.in_interface = "eth0"
            rule.protocol = "udp"
            rule.target = iptc.Target(rule, "DROP")
            match = rule.create_match("udp")
            match.sport = str(i)
            match.dport = "123"
            rule.add_match(match)
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.insert_rule(rule)
            blacklist_tmp = (i, time.time())
            blacklist.append(blacklist_tmp)
            logfile = open('/var/log/portfilter.log', 'a')
            logfile.write(str(time.time()-init_time)+ " ADDED "+ str(i)+ " ,FIREWALL SIZE="+ str(len(blacklist)) + " ,LOAD AVERAGE="+str(os.getloadavg()[0])+ " ,DATA SENT="+ str((get_bytes('tx')/1024/1024 - init_data)*8)+ " Mbps" +"\n")
            logfile.close()
            if (len(blacklist) > 0):
                for i in range(0, len(blacklist)):
                    if (i >= len(blacklist)):
                        break
                    if (int(time.time() - blacklist[i][1]) > timeout_arg):
                        try:
                            logfile = open('/var/log/portfilter.log', 'a')
                            logfile.write(str(time.time()-init_time)+ " TRYING TO REMOVE "+ str(blacklist[i][0])+" ,FIREWALL SIZE="+ str(len(blacklist)) + " ,LOAD AVERAGE="+str(os.getloadavg()[0]) + " ,DATA SENT="+ str((get_bytes('tx')/1024/1024 - init_data)*8)+ " Mbps" +"\n")
                            logfile.close()
                            rule = iptc.Rule()
                            rule.in_interface = "eth0"
                            rule.protocol = "udp"
                            rule.target = iptc.Target(rule, "DROP")
                            match = rule.create_match("udp")
                            match.sport = str(blacklist[i][0])
                            match.dport = "123"
                            rule.add_match(match)
                            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
                            chain.delete_rule(rule)
                            logfile = open('/var/log/portfilter.log', 'a')
                            logfile.write(str(time.time()-init_time)+ " DELTED "+ str(blacklist[i][0])+" ,FIREWALL SIZE="+ str(len(blacklist))+" ,LOAD AVERAGE="+str(os.getloadavg()[0])+ " ,DATA SENT="+ str((get_bytes('tx')/1024/1024 - init_data)*8)+ " Mbps" "\n")
                            logfile.close()
                            blacklist.pop(i)
                        except:
                            break
            #save_blacklist(blacklist_file)