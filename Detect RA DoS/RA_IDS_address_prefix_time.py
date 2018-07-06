import logging
import pyshark
import numpy as np
from scipy.stats import entropy

ewma_factor = 0.15
adaptive_threshold_variable = 0.25
alarm_count_max = 4


def numpy_shannon_entropy(labels, base=None):
    value, counts = np.unique(labels, return_counts=True)
    return entropy(counts, base=base)


def ewma(current_period_data_value, previous_period_ewma):
    current_period_ewma = (current_period_data_value * ewma_factor) + (previous_period_ewma * (1 - ewma_factor))
    return current_period_ewma


def adaptive_threshold_algorithm(previous_mean_value):
    return (1 + adaptive_threshold_variable) * previous_mean_value


def main():
    all_router_multicast = "ff02::1"
    first_iteration = True
    packet_type = "ICMPV6"
    time_window = 2.000000
    path_to_pcap_file = '/root/final_RA.pcap'
    pcap = pyshark.FileCapture(path_to_pcap_file)
    prefix_list = []
    source_IP_list = []
    destination_IP_list = []

    # create logger with 'spam_application'
    logger = logging.getLogger('RA_IDS_address_prefix_time')
    logger.setLevel(logging.DEBUG)
    # create file handler which logs even debug messages
    fh = logging.FileHandler('RA_IDS_address_prefix_time.log')
    fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)

    logger.info('---------- IDS Information ----------')
    logger.info('Window based on : {} seconds'.format(time_window))
    logger.info('EWMA factor used : {}'.format(ewma_factor))
    logger.info('Adaptive threshold variable used : {}'.format(adaptive_threshold_variable))
    logger.info('Maximum number of times threshold exceeds before raising an alarm : {}'.format(alarm_count_max))
    logger.info('-------------------------------------')

    start_time = pcap[0].sniff_time

    for pkt in pcap:
        current_time = pkt.sniff_time
        elapsed_time = current_time - start_time

        if pkt.highest_layer == packet_type:
            logger.debug('Packet is type ICMPv6')
            if pkt.icmpv6.type == "134":
                logger.debug('Packet is type ICMPv6 Router Advertisement 134')
                var_prefix = str(pkt.icmpv6.opt_prefix)
                prefix_list.append(var_prefix.replace(":", ""))

            if pkt.ipv6.dst == all_router_multicast:
                logger.debug('Packet Flow to destination {}'.format(all_router_multicast))
                var_dst = pkt.ipv6.dst
                destination_IP_list.append(var_dst.replace(":", ""))
                var_src = pkt.ipv6.src
                source_IP_list.append(var_src.replace(":", ""))

        else:
            pass
            logger.debug('Packet is NOT type ICMPv6')

        if elapsed_time.total_seconds() >= time_window:
            start_time = pkt.sniff_time
            logger.info('---------- Window Starts ----------')
            logger.info('Start time: {}'.format(start_time))
            logger.info('Current time: {}'.format(current_time))
            logger.info('Elapsed time: {}'.format(elapsed_time))

            logger.info('Calculating Shannon\'s entropy for address prefixes')
            logger.info('Prefix count: {}'.format(len(prefix_list)))
            entropy_prefix = numpy_shannon_entropy(prefix_list)
            logger.info('Entropy for address prefix : {}\n'.format(entropy_prefix))

            if first_iteration == True:
                logger.debug('In first iteration - calculating EWMA threshold')
                prefix_threshold = ewma(ewma_lambda, entropy_prefix, entropy_prefix)

                previous_prefix_threshold = prefix_threshold

                logger.info('prefix_threshold: {}'.format(prefix_threshold))
                first_iteration = False

            else:
                logger.debug('Not in first Iteration - calculating EWMA threshold')
                prefix_threshold = ewma(ewma_lambda, entropy_prefix, previous_prefix_threshold)

                previous_prefix_threshold = prefix_threshold

                logger.info('prefix_threshold: {}'.format(prefix_threshold))

                if entropy_prefix > prefix_threshold:
                    logger.info('RA Flooding Detected - entropy of prefix > threshold\n')
                    logger.info('entropy_prefix: {}'.format(entropy_prefix))
                    logger.info('prefix_threshold: {}\n'.format(prefix_threshold))

            # flush list
            prefix_list = []
            source_IP_list = []
            destination_IP_list = []
            logger.info("---------- Window Ends   ----------")


if __name__ == "__main__":
    main()
