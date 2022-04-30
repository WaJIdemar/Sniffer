import textwrap
from datetime import datetime, timezone
import socket
from unpacker import Unpacker


class Sniffer:
    output_file_name = 'sniff.pcap'
    tcp_session = {}
    TAB_1 = '\t - '
    TAB_2 = '\t\t - '
    TAB_3 = '\t\t\t - '
    TAB_4 = '\t\t\t\t - '

    DATA_TAB_1 = '\t '
    DATA_TAB_2 = '\t\t '
    DATA_TAB_3 = '\t\t\t '
    DATA_TAB_4 = '\t\t\t\t '

    def write_tcp_packets(self, tcp_packets: list[bytes]) -> None:
        """Write to pcap tcp session HTTP"""
        unpacker = Unpacker()
        for raw_data in tcp_packets:
            eth_header = unpacker.ethernet_head(raw_data)
            ipv4 = unpacker.ipv4_head(eth_header[3])
            tcp = unpacker.tcp_head(ipv4[6])
            key = ipv4[4] + "/" + ipv4[5]
            if key not in self.tcp_session:
                key = ipv4[5] + "/" + ipv4[4]
                if key not in self.tcp_session:
                    self.tcp_session[key] = []
                    self.tcp_session[key].append(raw_data)
                else:
                    self.tcp_session[key].append(raw_data)
            else:
                self.tcp_session[key].append(raw_data)

            if tcp[9] == 1 or tcp[7] == 1:
                buffer = []
                for packet_session in self.tcp_session[key]:
                    eth_header = unpacker.ethernet_head(packet_session)
                    ipv4 = unpacker.ipv4_head(eth_header[3])
                    tcp = unpacker.tcp_head(ipv4[6])
                    buffer.append(packet_session)
                    if len(tcp[10]) > 0:
                        try:
                            http = tcp[10].decode("utf-8")
                            if "HTTP" in http:
                                for packet in buffer:
                                    self.write_packet(packet)
                        except UnicodeError as e:
                            break
                del self.tcp_session[key]

    def write_global_header(self):
        """Write global pcap header in file"""
        with open(self.output_file_name, 'wb') as output_file:
            magic_number = b"\xd4\xc3\xb2\xa1"
            version_major = b"\x02\x00"
            version_minor = b"\x04\x00"
            thiszone = b"\x00\x00\x00\x00"
            sigfigs = b"\x00\x00\x00\x00"
            snaplen = b"\xff\xff\x00\x00"
            network = b"\x01\x00\x00\x00"  # Only for Ethernet
            global_header = magic_number + version_major + version_minor + \
                            thiszone + sigfigs + snaplen + network
            output_file.write(global_header)

    def write_packet(self, data: bytes):
        """Write packet with self header in file"""
        with open(self.output_file_name, 'ab') as output_file:
            now_ts = datetime.now(timezone.utc).timestamp()
            ts_sec = int(now_ts).to_bytes(4, byteorder='little')
            ts_usec = int(now_ts % 1 * 1000).to_bytes(4, byteorder='little')
            incl_len = len(data).to_bytes(4, byteorder='little')
            orig_len = incl_len
            packet_header = ts_sec + ts_usec + incl_len + orig_len
            output_file.write(packet_header + data)

    def sniff(self):
        """Start sniffer in while True"""
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                   socket.ntohs(3))
        self.write_global_header()
        while True:
            raw_data = raw_socket.recvfrom(65535)[0]
            if len(raw_data) != 0:
                self.write_packet(raw_data)

    def scan_tcp_session(self):
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                   socket.ntohs(3))
        unpacker = Unpacker()
        buffer_tcp = []
        self.write_global_header()
        while True:
            raw_data = raw_socket.recvfrom(65535)[0]
            eth_header = unpacker.ethernet_head(raw_data)
            if eth_header[2] == 8:
                ipv4 = unpacker.ipv4_head(eth_header[3])
                if ipv4[3] == 6:
                    buffer_tcp.append(raw_data)

            if len(buffer_tcp) > 10:
                self.write_tcp_packets(buffer_tcp.copy())
                buffer_tcp.clear()

    def sniff_and_print(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        unpacker = Unpacker()
        self.write_global_header()
        while True:
            raw_data, addres = s.recvfrom(65535)
            ethernet_header = unpacker.ethernet_head(raw_data)
            print('\nEthernet Frame:')
            print(
                f'Destination: {ethernet_header[0]}, Source: {ethernet_header[1]}, Protocol: {ethernet_header[2]} ')

            if ethernet_header[2] == 8:
                ipv4 = unpacker.ipv4_head(ethernet_header[3])
                print(self.TAB_1 + 'IPv4 Packet:')
                print(
                    self.TAB_2 + f'Version: {ipv4[0]}, Header Length: {ipv4[1]}, TTL: {ipv4[2]}')
                print(
                    self.TAB_2 + f'Protocol: {ipv4[3]}, Source: {ipv4[4]}, Target: {ipv4[5]}')
                if ipv4[3] == 1:
                    icmp_header = unpacker.icmp_packet(ipv4[6])
                    print(self.TAB_1 + 'ICMP Packet:')
                    print(
                        self.TAB_2 + f'Type{icmp_header[0]}, Code: {icmp_header[1]}, Checksum: {icmp_header[2]},')
                    print(self.TAB_2 + 'Data:')
                    print(self.format_multi_line(self.DATA_TAB_3,
                                                 icmp_header[3]))
                elif ipv4[3] == 6:
                    tcp = unpacker.tcp_head(ipv4[6])
                    print(self.TAB_1 + 'TCP Segment:')
                    print(
                        self.TAB_2 + f'Source Port: {tcp[0]}, Destination Port: {tcp[1]}')
                    print(
                        self.TAB_2 + f'Sequence: {tcp[2]}, Acknowledgment: {tcp[3]}')
                    print(self.TAB_2 + 'Flags:')
                    print(
                        self.TAB_3 + f'URG: {tcp[4]}, ACK: {tcp[5]}, PSH: {tcp[6]}')
                    print(
                        self.TAB_3 + f'RST: {tcp[7]}, SYN: {tcp[8]}, FIN: {tcp[9]}')
                    if len(tcp[10]) > 0:
                        try:
                            http = tcp[10].decode('utf-8')
                            print(self.TAB_2 + 'HTTP Data:')
                            for line in http.split('\n'):
                                print(self.DATA_TAB_3 + line)
                        except UnicodeDecodeError:
                            print(self.TAB_2 + 'TCP Data:')
                            print(self.format_multi_line(self.DATA_TAB_3,
                                                         tcp[10]))

                elif ipv4[3] == 17:
                    udp = unpacker.udp_head(ipv4[6])
                    print(self.TAB_1 + 'UDP Segment:')
                    print(
                        self.TAB_2 + f'Source Port: {udp[0]}, Destination Port: {udp[1]}, Length: {udp[2]}')
                    print(self.format_multi_line(self.DATA_TAB_3, udp[3]))
            self.write_packet(raw_data)

    def format_multi_line(self, prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join(
            [prefix + line for line in textwrap.wrap(string, size)])
