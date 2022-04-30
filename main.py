import argparse

from sniffer import Sniffer


def start_sniff():
    sniffer = Sniffer()
    sniffer.sniff()


def start_scan_tcp_session():
    sniffer = Sniffer()
    sniffer.scan_tcp_session()


def start_sniff_and_print():
    sniffer = Sniffer()
    sniffer.sniff_and_print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Simple sniffer. Running without parameters will just save all packages to pcap')
    parser.add_argument('-sh', dest='sh', action='store_true',
                        help='Capture of PCAP recording packets and output of packets to the console')
    parser.add_argument('-t', dest="tcp", action='store_true',
                        help='Capturing TCP session http packets')
    args = parser.parse_args()
    if args.sh and args.tcp:
        print('Select only one key')

    if args.sh:
        start_sniff_and_print()
    elif args.tcp:
        start_scan_tcp_session()
    else:
        start_sniff()
