from argparse import ArgumentParser
from sniffer import Sniffer

if __name__ == "__main__":
    parser = ArgumentParser(
        description='Simple sniffer. Running without parameters will just '
                    'save all packages to pcap')
    parser.add_argument('-sh', dest='sh', action='store_true',
                        help='Capture of PCAP recording packets and output of '
                             'packets to the console')
    parser.add_argument('-t', dest="tcp", action='store_true',
                        help='Capturing TCP session http packets')
    args = parser.parse_args()
    if args.sh and args.tcp:
        print('Select only one key')
    sniffer = Sniffer()
    if args.sh:
        sniffer.sniff_and_print()
    elif args.tcp:
        sniffer.scan_tcp_session()
    else:
        sniffer.sniff()
