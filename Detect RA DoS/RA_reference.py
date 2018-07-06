import time
import math
import pyshark
import numpy as np
import collections
import scipy as sc
import pandas
from datetime import datetime
from scipy.stats import entropy
from collections import Counter
import matplotlib.pyplot as plt
ewma = pandas.ewma


path_to_file = '/root/final_RA.pcap'
wireshark_filter = 'icmpv6.type == 134'
# pcap = pyshark.FileCapture(path_to_file, display_filter=wireshark_filter)
pcap = pyshark.FileCapture(path_to_file)
t_time = 2.000000


def ewma(ewma_lambda, current_period_data_value, previous_period_ewma):
    current_period_ewma = (current_period_data_value * ewma_lambda) + (previous_period_ewma * (1 - ewma_lambda))
    return current_period_ewma


def slice_time():
    my_start_time = pcap[0].sniff_time

    for pkt in pcap:
        current_packet_time = pkt.sniff_time
        elapsed_time = current_packet_time - my_start_time
        if elapsed_time.total_seconds() >= t_time:
            my_start_time = pkt.sniff_time
            print "my_start_time: ", my_start_time
            print "current_packet_time: ", current_packet_time
            print "elapsed_time: ", elapsed_time.total_seconds()


def get_prefix():
    prefix_list = []
    for pkt in pcap:
        prefix_list.append(pkt.icmpv6.opt_prefix)

    return prefix_list


def get_source_ip():
    source_ip = []
    for pkt in pcap:
        source_ip.append(pkt.ipv6.src_host)

    return source_ip


def get_source_mac():
    source_mac = []
    for pkt in pcap:
        source_mac.append(pkt.ipv6.src_sa_mac)

    return source_mac


def get_destination():
    destination_ip = []
    for pkt in pcap:
        destination_ip.append(pkt.ipv6.dst)

    return destination_ip


def get_default_router_preference_changes_linkaddr():
    prf_flag = []
    for pkt in pcap:
        if pkt.icmpv6.nd_ra_flag_prf == '1':
            prf_flag.append(pkt.icmpv6.opt_src_linkaddr)

    return prf_flag


def calculate_shannon_entropy_2(data, unit='natural'):
    base = {
        'shannon': 2.,
        'natural': math.exp(1),
        'hartley': 10.
    }

    if len(data) <= 1:
        return 0

    counts = Counter()

    for d in data:
        counts[d] += 1

    probs = [float(c) / len(data) for c in counts.values()]
    probs = [p for p in probs if p > 0.]

    ent = 0

    for p in probs:
        if p > 0.:
            ent -= p * math.log(p, base[unit])

    return ent


def calculate_shannon_entropy_4(data):
    p_data = data.value_counts() / len(data)  # calculates the probabilities
    entropy = sc.stats.entropy(p_data)  # input probabilities to get the entropy
    return entropy


def calculate_shannon_entropy_5(labels, base=None):
    value, counts = np.unique(labels, return_counts=True)
    return entropy(counts, base=base)


def entropy_new(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())


packet_type = "ICMPV6"
prefix_list = []
source_IP = []
dest_IP = []
alpha = 0.55
dest = "ff02::1"
STATIC_PREFIX = ['2012:9c78:de9c:d40f::', '2012:9c78:119d:d40f::', '2012:9c78:449d:d40f::', '2012:9c78:779d:d40f::']
STATIC_SOURCE = ['fe80::9c:77dd:9cd4:f01', 'fe80::9c:7710:9dd4:f01', 'fe80::9c:7743:9dd4:f01', 'fe80::9c:7776:9dd4:f01']
ewma_lambda = 0.2
first_iter = True

# MAIN
print 'Starting IDS...'
start_time = pcap[0].sniff_time

for pkt in pcap:
    current_time = pkt.sniff_time
    elapsed_time = current_time - start_time

    if pkt.highest_layer == packet_type:
        # print 'ICMPv6'
        if pkt.icmpv6.type == "134":
            # print 'RA packet'
            var_prefix = str(pkt.icmpv6.opt_prefix)
            prefix_list.append(var_prefix.replace(":", ""))

        if pkt.ipv6.dst == dest:
            # print "RA Packet Flow Detected!"
            var_dst = pkt.ipv6.dst
            var_src = pkt.ipv6.src
            dest_IP.append(var_dst.replace(":", ""))
            source_IP.append(var_src.replace(":", ""))

    else:
        pass
    # print 'NOT ICMPv6'

    if elapsed_time.total_seconds() >= t_time:
        start_time = pkt.sniff_time
        print "############### Window Starts ###############"
        print "start_time: ", start_time
        print "current_time: ", current_time
        print "elapsed_time: ", elapsed_time.total_seconds()

        """		
        print 'calculate shannon\'s entropy for address prefixes'
        print 'prefix_list count: ', len(prefix_list)
        entropy_prefix5 = calculate_shannon_entropy_5(prefix_list)
        print 'Entropy for address prefix using calculate_shannon_entropy_5: ', entropy_prefix5
        print ''
        """

        print 'calculate shannon\'s entropy for flow based - source IP'
        print 'source_IP count: ', len(source_IP)
        entropy_source_IP_1 = calculate_shannon_entropy_5(source_IP)
        print 'Entropy for flow based - source IP using calculate_shannon_entropy_5: ', entropy_source_IP_1
        print ''



        print 'calculate shannon\'s entropy for flow based - source IP'
        print 'source_IP count: ', len(source_IP)
        entropy_source_IP_2 = calculate_shannon_entropy_2(source_IP)
        print 'Entropy for flow based - source IP using entropy_new: ', entropy_source_IP_2
        print ''

        expAverage = pandas.stats.moments.ewma(entropy_source_IP_2, com=50)

        print "EWMA = ", expAverage
        """
        print 'calculate shannon\'s entropy for flow based - destination IP'
        print 'dest_IP count: ', len(dest_IP)
        entropy_destination_IP = calculate_shannon_entropy_5(dest_IP)
        print 'Entropy for flow based - destination IP using calculate_shannon_entropy_5: ', entropy_destination_IP
        print ''
        

        print "PREFIX: ", prefix_list[1:5]
        print "SOURCE: ", source_IP[1:5]
        print "DESTINATION: ", dest_IP[1:5]
        print ''
        

        if first_iter == True:
            print 'In first Iteration'
            prefix_threshold = ewma(ewma_lambda, entropy_prefix5, entropy_prefix5)
            source_IP_threshold = ewma(ewma_lambda, entropy_source_IP, entropy_source_IP)

            previous_prefix_threshold = prefix_threshold
            previous_source_IP_threshold = source_IP_threshold

            print "prefix_threshold: ", prefix_threshold
            print "source_IP_threshold: ", source_IP_threshold
            print ''
            first_iter = False
        else:
            print 'NOT in first Iteration'
            prefix_threshold = ewma(ewma_lambda, entropy_prefix5, previous_prefix_threshold)
            source_IP_threshold = ewma(ewma_lambda, entropy_source_IP, previous_source_IP_threshold)

            previous_prefix_threshold = prefix_threshold
            previous_source_IP_threshold = source_IP_threshold

            print "prefix_threshold: ", prefix_threshold
            print "source_IP_threshold: ", source_IP_threshold
            print ''
        """
        # flush list
        prefix_list = []
        source_IP = []
        dest_IP = []
        print "############### Window Ends ###############"
        print ''