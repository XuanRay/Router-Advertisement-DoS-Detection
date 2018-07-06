import logging
import pyshark
import numpy as np
from scipy.stats import entropy

ewma_factor = 0.2
adaptive_threshold_variable = 0.2
alarm_count_max = 4


def numpy_shannon_entropy(labels, base=None):
    value, counts = np.unique(labels, return_counts=True)
    return entropy(counts, base=base)


def ewma(current_period_data_value, previous_period_ewma):
    current_period_ewma = (current_period_data_value * ewma_factor) + (previous_period_ewma * (1 - ewma_factor))
    return current_period_ewma


def lower_adaptive_threshold_algorithm(previous_mean_value):
    return (1 - adaptive_threshold_variable) * previous_mean_value


def upper_adaptive_threshold_algorithm(previous_mean_value):
    return (1 + adaptive_threshold_variable) * previous_mean_value


def main():
    first_window = True
    packet_type = "ICMPV6"
    packet_window = 50
    path_to_pcap_file = '/root/final_RA.pcap'
    pcap = pyshark.FileCapture(path_to_pcap_file)

    # create logger with name 'RA_IDS'
    logger = logging.getLogger('RA_IDS')
    logger.setLevel(logging.DEBUG)
    # create file handler which logs even debug messages
    fh = logging.FileHandler('RA_IDS.log')
    fh.setLevel(logging.INFO)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    # ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)

    logger.info('---------- IDS Information ----------')
    logger.info('Window based on : {} packet count'.format(packet_window))
    logger.info('EWMA factor used : {}'.format(ewma_factor))
    logger.info('Adaptive threshold variable used : {}'.format(adaptive_threshold_variable))
    logger.info('Maximum number of times threshold exceeds before raising an alarm : {}'.format(alarm_count_max))
    logger.info('-------------------------------------')

    destination_IP_list = []
    source_IP_RA_msg_list = []

    alarm_count_destination_ip = 0
    alarm_count_RA_message_source_ip = 0
    packet_count = 0
    window_count = 0
    temp = 0
    alarm_flag_destination_IP = False
    alarm_flag_RA_message_source_ip  = False

    for pkt in pcap:
        temp = temp + 1

        try:
            # ipv4
            if pkt.ip:
                dst_addr = str(pkt.ip.dst)
                destination_IP_list.append(dst_addr.replace(".", ""))

        except AttributeError as e:
            # ignore packets that aren't or IPv4
            pass

        try:
            # ipv6
            if pkt.ipv6:
                dst_addr = str(pkt.ipv6.dst)
                destination_IP_list.append(dst_addr.replace(":", ""))

        except AttributeError as e:
            # ignore packets that aren't IPv6
            pass

        if pkt.highest_layer == packet_type:
            logger.debug('Packet is type ICMPv6')
            if pkt.icmpv6.type == "134":
                logger.debug('Packet is type ICMPv6 Router Advertisement 134')
                var_source_IP_RA_msg = str(pkt.ipv6.src)
                source_IP_RA_msg_list.append(var_source_IP_RA_msg.replace(":", ""))

        else:
            pass
            logger.debug('Packet is NOT type ICMPv6')

        if packet_count >= packet_window:
            window_count = window_count + 1

            logger.info('---------- Window Starts ----------')
            logger.info('Current packet count: {}'.format(packet_count))

            logger.info('Calculating Shannon\'s entropy for Destination IP address')
            logger.info('Destination IP count: {}'.format(len(destination_IP_list)))
            entropy_destination_ip = numpy_shannon_entropy(destination_IP_list)
            logger.info('Entropy for Destination IP address : {}\n'.format(entropy_destination_ip))

            logger.info('Calculating Shannon\'s entropy for RA message Source IP address')
            logger.info('Source IP count: {}'.format(len(source_IP_RA_msg_list)))
            entropy_RA_message_source_ip = numpy_shannon_entropy(source_IP_RA_msg_list)
            logger.info('Entropy for RA message Source IP address : {}\n'.format(entropy_RA_message_source_ip))

            if first_window == True:
                logger.debug('EWMA for destination_IP - 1st iteration')
                this_window_ewma_value_entropy_destination_ip = ewma(entropy_destination_ip, entropy_destination_ip)
                # logger.info('EWMA value for destination_IP: {}'.format(this_window_ewma_value_entropy_destination_ip))
                previous_window_ewma_value_entropy_destination_ip = this_window_ewma_value_entropy_destination_ip

                logger.debug('EWMA for RA message source_IP - 1st iteration')
                this_window_ewma_value_entropy_RA_message_source_ip = ewma(entropy_RA_message_source_ip,
                                                                           entropy_RA_message_source_ip)
                # logger.info('EWMA value for RA message source_IP: {}'.format(this_window_ewma_value_entropy_RA_message_source_ip))
                previous_window_ewma_value_RA_message_source_ip = this_window_ewma_value_entropy_RA_message_source_ip

                first_window = False

            else:
                if alarm_flag_destination_IP == False:
                    adaptive_threshold_destination_IP = lower_adaptive_threshold_algorithm(
                        previous_window_ewma_value_entropy_destination_ip)
                    logger.info('Adaptive threshold value for destination_IP: {}'.format(adaptive_threshold_destination_IP))

                if alarm_flag_RA_message_source_ip == False:
                    adaptive_threshold_RA_message_source_ip = upper_adaptive_threshold_algorithm(
                        previous_window_ewma_value_RA_message_source_ip)
                    logger.info('Adaptive threshold value for RA message source_IP: {}'.format(
                        adaptive_threshold_RA_message_source_ip))

                # logger.debug('EWMA for destination_IP - Not in 1st iteration')
                this_window_ewma_value_entropy_destination_ip = ewma(entropy_destination_ip,
                                                                     previous_window_ewma_value_entropy_destination_ip)
                # logger.info('EWMA value for destination_IP: {}'.format(this_window_ewma_value_entropy_destination_ip))
                previous_window_ewma_value_entropy_destination_ip = this_window_ewma_value_entropy_destination_ip

                # logger.debug('EWMA for RA message source_IP - Not in 1st iteration')
                this_window_ewma_value_entropy_RA_message_source_ip = ewma(entropy_RA_message_source_ip,
                                                                           previous_window_ewma_value_RA_message_source_ip)
                # logger.info('EWMA value for RA message source_IP: {}'.format(this_window_ewma_value_entropy_RA_message_source_ip))
                previous_window_ewma_value_RA_message_source_ip = this_window_ewma_value_entropy_RA_message_source_ip

                if float(entropy_destination_ip) <= float(adaptive_threshold_destination_IP):

                    alarm_count_destination_ip = alarm_count_destination_ip + 1

                    if alarm_count_destination_ip >= alarm_count_max:

                        logger.info('Flooding Detected Attack!')
                        logger.info('Entropy for destination IP: {}'.format(entropy_destination_ip))
                        logger.info('Adaptive threshold value for destination IP: {}'.format(adaptive_threshold_destination_IP))
                        logger.info('ALARM COUNT: {}'.format(alarm_count_destination_ip))
                        alarm_flag_destination_IP = True
                        alarm_count_destination_ip = 0
                        logger.info('Packet #: {}'.format(temp))

                        # determine if flooded msgs is type 134
                        if entropy_RA_message_source_ip >= adaptive_threshold_RA_message_source_ip:

                            alarm_count_RA_message_source_ip = alarm_count_RA_message_source_ip + 1
                            logger.info('RA Flooding Detected Attack!')
                            logger.info('alarm count: {}'.format(alarm_count_RA_message_source_ip))

                            if alarm_count_RA_message_source_ip >= alarm_count_max:
                                logger.info('RA Flooding Detected Attack!')
                                logger.info('Entropy for RA message source_IP: {}'.format(entropy_destination_ip))
                                logger.info(
                                    'Adaptive threshold value : {}'.format(adaptive_threshold_RA_message_source_ip))
                                logger.info('ALARM COUNT: {}'.format(alarm_count_RA_message_source_ip))
                                alarm_flag_RA_message_source_ip = True
                                alarm_count_RA_message_source_ip = 0
                                logger.info('ALARM COUNT RESET: {}'.format(alarm_count_RA_message_source_ip))
                                logger.info('WINDOW COUNT: {}'.format(window_count))
                                exit(1)
                else:
                    logger.info('NO Flooding Detected...')
                    logger.info('Entropy for destination IP : {}'.format(entropy_destination_ip))
                    logger.info('Adaptive threshold value : {}'.format(adaptive_threshold_destination_IP))

            # flush list
            destination_IP_list = []
            source_IP_RA_msg_list = []
            packet_count = 0
            logger.info("---------- Window Ends   ----------\n")
        packet_count = packet_count + 1


if __name__ == "__main__":
    main()
