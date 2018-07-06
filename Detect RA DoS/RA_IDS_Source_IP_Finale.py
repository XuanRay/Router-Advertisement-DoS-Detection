import csv
import logging
import pyshark
import collections
import numpy as np
from scipy.stats import entropy

# create logger with name 'RA_IDS_flow_based_packet_count'
logger = logging.getLogger('RA_IDS_Source_IP_Final')
logger.setLevel(logging.INFO)
# create file handler which logs even debug messages
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
fh = logging.FileHandler('implementation.log')
fh.setLevel(logging.INFO)
formatter = logging.Formatter('%(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)

ewma_factor = 0.1
packet_window = 50
alarm_count_max = 4
adaptive_threshold_variable = 0.1


# pcap_location = '/root/Desktop/Pcaps_report/fragmentation3.pcap'
pcap_location = '/root/Desktop/Pcaps_report/hop_by_hop3.pcap'
# pcap_location = '/root/Desktop/Pcaps/fragmentation3.pcap'
# pcap_location = '/root/Desktop/pcap_finale/normal.pcap'

path_to_pcap_file = pcap_location
pcap = pyshark.FileCapture(path_to_pcap_file)

"""
False Negative; situation where anomalous events are recorded as normal.
if entropy > 0 :
	but no alarm

False Positive;  situation where normal events are detected as anomaly.
if entropy == 0 :
	alarm

True Negative; situation where normal events are truely recorded as normal.
if entropy == 0:
	no alarm

True Positive; situation where anomalous events are truely detected as anomaly.
if entropy > 0:
	alarm
"""

def numpy_shannon_entropy(labels, base=None):
    value, counts = np.unique(labels, return_counts=True)
    return entropy(counts, base=base)


def ewma(current_period_data_value, previous_period_ewma):
    logger.info('Calculating EWMA')

    current_period_data_value = (round(current_period_data_value, 5))
    previous_period_ewma = (round(previous_period_ewma, 5))
    current_period_ewma = (current_period_data_value * ewma_factor) + (previous_period_ewma * (1 - ewma_factor))
    logger.info('current_period_ewma = (current_period_data_value * ewma_factor) + (previous_period_ewma * (1 - ewma_factor))')
    logger.info('current_period_ewma = ({} * {}) + ({} * (1 - {}))'.format(current_period_data_value,ewma_factor,previous_period_ewma,ewma_factor))
    logger.info('current_period_ewma = {}'.format(current_period_ewma))
    return current_period_ewma


def adaptive_threshold_algorithm(previous_mean_value):
    logger.info('Calculating Adaptive Threshold Algorithm')
    adaptive_threshold_algorithm_value = (1 + adaptive_threshold_variable) * previous_mean_value
    logger.info('adaptive_threshold_algorithm_value = 1 + adaptive_threshold_variable) * previous_mean_value')
    logger.info('adaptive_threshold_algorithm_value = (1 + {}) * {}'.format(adaptive_threshold_variable,previous_mean_value))
    logger.info('adaptive_threshold_algorithm_value = {}'.format(adaptive_threshold_algorithm_value))
    return adaptive_threshold_algorithm_value

def main():
    window_count = 0
    first_window = True
    calculate_threshold = True
    packet_type = "ICMPV6"

    logger.info('---------- IDS Information ----------')
    logger.info('Dataset : {}'.format(pcap_location))
    logger.info('Window based on : {} packet count'.format(packet_window))
    logger.info('EWMA factor used : {}'.format(ewma_factor))
    logger.info('Adaptive threshold variable used : {}'.format(adaptive_threshold_variable))
    logger.info('Maximum number of times threshold exceeds before raising an alarm : {}'.format(alarm_count_max))
    logger.info('-------------------------------------')

    alarm_count = 0
    packet_count = 0
    RA_packet_count = 0
    source_IP_list = []

    false_negative_count = 0
    false_positive_count = 0
    true_negative_count = 0
    true_positive_count = 0
    _threshold = []
    _entropy = []

    _my_temp = []


    for pkt in pcap:

        if pkt.highest_layer == packet_type:
            logger.debug('Packet is type ICMPv6 RA')
            if pkt.icmpv6.type == "134":
                RA_packet_count = RA_packet_count + 1
                var_src = pkt.ipv6.src
                source_IP_list.append(var_src.replace(":", ""))

                current_time = pkt.sniff_time

        else:
            pass
            logger.debug('Packet is NOT type ICMPv6 RA')

        if packet_count >= packet_window:
            window_count = window_count + 1
            logger.info('---------- Window Starts ----------')
            logger.info('Sliding window number = {}'.format(window_count))
            logger.info('Source IP address count = {}'.format(len(source_IP_list)))
            logger.info('List of Source IP address = {}'.format(source_IP_list))
            entropy_source_IP = numpy_shannon_entropy(source_IP_list)
            entropy_source_IP = (round(entropy_source_IP, 5))
            logger.info('Calculating Entropy')

            logger.info('Entropy of Source IP address = {}'.format(entropy_source_IP))

            if first_window == True:
                # In first iteration - calculating EWMA
                this_window_ewma_value = ewma(entropy_source_IP, entropy_source_IP)
                previous_window_ewma_value = this_window_ewma_value
                first_window = False

            else:
                this_window_ewma_value = ewma(entropy_source_IP, previous_window_ewma_value)
                previous_window_ewma_value = this_window_ewma_value

            if calculate_threshold == True:
                adaptive_threshold = adaptive_threshold_algorithm(previous_window_ewma_value)
                adaptive_threshold = (round(adaptive_threshold, 5))

            logger.info('Comparison between Entropy value and Threshold Value')
            logger.info('Entropy Value = {} vs Threshold Value = {}'.format(entropy_source_IP,adaptive_threshold))


            if float(entropy_source_IP) > float(adaptive_threshold):
                alarm_count = alarm_count + 1
                logger.info('ALARM # {}'.format(alarm_count))

                if alarm_count >= alarm_count_max:
                    logger.info('ALARM!!! RA Flooding Detected!!!')
                    logger.info('Entropy for source IP address : {}'.format(entropy_source_IP))
                    logger.info('Adaptive threshold value : {}'.format(adaptive_threshold))
                    calculate_threshold = False

                    if float(entropy_source_IP) <= 0.0:
                        false_positive_count = false_positive_count + 1
                    if float(entropy_source_IP) > 0.0:
                        true_positive_count = true_positive_count + 1
            else:
                logger.info('NO! RA Flooding Detected...')
                logger.info('Entropy for source IP address : {}'.format(entropy_source_IP))
                logger.info('Adaptive threshold value : {}'.format(adaptive_threshold))
                alarm_count = 0
                calculate_threshold = True

                if float(entropy_source_IP) > 0:
                    false_negative_count = false_negative_count + 1
                    logger.info('False Negative Sliding window number = {}'.format(window_count))
                    _my_temp.append(window_count)
                if float(entropy_source_IP) == 0:
                    true_negative_count = true_negative_count + 1

            _threshold.append(adaptive_threshold)
            _entropy.append(entropy_source_IP)


            # flush list
            source_IP_list = []
            packet_count = 0

            logger.info('false positive count: {}'.format(false_positive_count))
            logger.info('false negative count: {}'.format(false_negative_count))
            logger.info('true positive count: {}'.format(true_positive_count))
            logger.info('true negative count: {}'.format(true_negative_count))

            logger.info("---------- Window Ends   ----------\n")
        packet_count = packet_count + 1

    logger.info("Entropy: {}".format(_entropy))
    logger.info("Threshold: {}".format(_threshold))

    f = open('entropy.csv', 'w')
    for entries in _entropy:
        f.write(str(entries) + '\n')

    f.close()

    f = open('threshold.csv', 'w')
    for entries in _threshold:
        f.write(str(entries) + '\n')

    f.close()

    f = open('error.csv', 'w')
    for entries in _my_temp:
        f.write(str(entries) + '\n')

    f.close()


if __name__ == "__main__":
    main()
