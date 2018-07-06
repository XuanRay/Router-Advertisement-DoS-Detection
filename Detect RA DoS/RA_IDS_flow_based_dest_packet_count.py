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
    first_window = True
    all_router_multicast = "ff02::1"
    packet_type = "ICMPV6"
    packet_window = 100
    path_to_pcap_file = '/root/final_RA.pcap'
    pcap = pyshark.FileCapture(path_to_pcap_file)

    # create logger with name 'RA_IDS_flow_based_packet_count'
    logger = logging.getLogger('RA_IDS_flow_based_dest_packet_count')
    logger.setLevel(logging.DEBUG)
    # create file handler which logs even debug messages
    fh = logging.FileHandler('RA_IDS_flow_based_dest_packet_count.log')
    fh.setLevel(logging.INFO)
    # create console handler with a higher log level
    # ch = logging.StreamHandler()
    # ch.setLevel(logging.INFO)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    # ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    # logger.addHandler(ch)

    logger.info('---------- IDS Information ----------')
    logger.info('Window based on : {} packet count'.format(packet_window))
    logger.info('EWMA factor used : {}'.format(ewma_factor))
    logger.info('Adaptive threshold variable used : {}'.format(adaptive_threshold_variable))
    logger.info('Maximum number of times threshold exceeds before raising an alarm : {}'.format(alarm_count_max))
    logger.info('-------------------------------------')

    alarm_count = 0
    packet_count = 0
    destination_IP_list = []

    for pkt in pcap:

        if pkt.highest_layer == packet_type:
            logger.debug('Packet is type ICMPv6')

            if pkt.ipv6.dst == all_router_multicast:
                logger.debug('Packet Flow to destination {}'.format(all_router_multicast))
                var_src = pkt.ipv6.src
                source_IP_list.append(var_src.replace(":", ""))

        else:
            pass
            logger.debug('Packet is NOT type ICMPv6')

        if packet_count >= packet_window:
            logger.info('---------- Window Starts ----------')
            logger.info('Current packet count: {}'.format(packet_count))
            logger.info('Calculating Shannon\'s entropy for flow based - destination IP')
            logger.info('Source_IP count: {}'.format(len(source_IP_list)))
            entropy_source_IP = numpy_shannon_entropy(source_IP_list)
            logger.info('Entropy for flow based - source IP u: {}\n'.format(entropy_source_IP))

            if first_window == True:
                # logger.debug('In first iteration - calculating EWMA')
                this_window_ewma_value = ewma(entropy_source_IP, entropy_source_IP)
                logger.info('EWMA value : {}'.format(this_window_ewma_value))
                previous_window_ewma_value = this_window_ewma_value
                first_window = False
            else:
                adaptive_threshold = adaptive_threshold_algorithm(previous_window_ewma_value)
                logger.info('Adaptive threshold value : {}'.format(adaptive_threshold))

                logger.debug('Not in first Iteration - calculating EWMA')
                this_window_ewma_value = ewma(entropy_source_IP, previous_window_ewma_value)
                logger.info('EWMA value : {}'.format(this_window_ewma_value))
                previous_window_ewma_value = this_window_ewma_value

                if float(entropy_source_IP) > float(adaptive_threshold):
                    alarm_count = alarm_count + 1

                    if alarm_count >= alarm_count_max:
                        logger.info('RA Flooding Detected!')
                        logger.info('Entropy for flow based - source IP u: {}\n'.format(entropy_source_IP))
                        logger.info('Adaptive threshold value : {}'.format(adaptive_threshold))
                        logger.info('ALARM COUNT: {}'.format(alarm_count))
                        alarm_count = 0
                        logger.info('ALARM COUNT RESET: {}'.format(alarm_count))
                else:
                    logger.info('NO! RA Flooding Detected...')
                    logger.info('Entropy for flow based - source IP u: {}\n'.format(entropy_source_IP))
                    logger.info('Adaptive threshold value : {}'.format(adaptive_threshold))

            # flush list
            source_IP_list = []
            packet_count = 0
            logger.info("---------- Window Ends   ----------\n")
        packet_count = packet_count + 1


if __name__ == "__main__":
    main()
