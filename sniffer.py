from _socket import ntohs
from datetime import datetime, timezone
from socket import socket, AF_PACKET, SOCK_RAW
from printer import Printer
from unpacker import Unpacker
from collections import defaultdict
from os import mkdir, sep
from os.path import exists


class Sniffer:
    output_file_name = 'sniff.pcap'
    output_dir = ""
    tcp_session = defaultdict(list[bytes])

    def analyzes_tcp_packets(self, tcp_packets: list[bytes]) -> None:
        """Analyzes TCP packets for the presence of HTTP"""
        unpacker = Unpacker()
        for raw_data in tcp_packets:
            destination_mac, source_mac, type_protocol, data \
                = unpacker.get_ethernet_head(raw_data)
            ip_version, ip_header_length, ttl, transport_proto, source_ip, \
            target_ip, data = unpacker.get_ipv4_head(data)
            source_port, destination_port, sequence, acknowledgment, flag_urg, \
            flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data \
                = unpacker.get_tcp_head(data)
            key = source_ip + "/" + target_ip
            if key not in self.tcp_session:
                key = target_ip + "/" + source_ip
                if key not in self.tcp_session:
                    self.tcp_session[key] = []

            self.tcp_session[key].append(raw_data)

            if flag_fin == 1 or flag_rst == 1:
                self.write_tcp_session(key)

    def write_tcp_session(self, key: str) -> None:
        """Write to pcap TCP session HTTP"""
        unpacker = Unpacker()
        buffer = []
        is_http = False
        for packet_session in self.tcp_session[key]:
            source_port, destination_port, sequence, acknowledgment, \
            flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
            data = unpacker.get_tcp_packet(packet_session)
            buffer.append(packet_session)
            if len(data) > 0:
                try:
                    http = data.decode("utf-8")
                    if "HTTP" in http:
                        is_http = True
                except UnicodeError:
                    pass
        if is_http:
            date_format = "%Y-%m-%d-%H.%M.%S"
            temp_file_name = datetime.now().strftime(date_format)
            suffix = ""
            count = 1
            while exists(self.output_dir + temp_file_name + suffix):
                suffix = f"({count})"
                count += 1
            self.output_file_name = temp_file_name + suffix
            self.write_global_header()
            for packet in buffer:
                self.write_packet(packet)
        del self.tcp_session[key]

    def write_global_header(self) -> None:
        """Write global pcap header in file"""
        with open(self.output_dir + self.output_file_name,
                  'wb') as output_file:
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

    def write_packet(self, data: bytes) -> None:
        """Write packet with self header in file"""
        with open(self.output_dir + self.output_file_name,
                  'ab') as output_file:
            now_ts = datetime.now(timezone.utc).timestamp()
            ts_sec = int(now_ts).to_bytes(4, byteorder='little')
            ts_usec = int(now_ts % 1 * 1000).to_bytes(4, byteorder='little')
            incl_len = len(data).to_bytes(4, byteorder='little')
            orig_len = incl_len
            packet_header = ts_sec + ts_usec + incl_len + orig_len
            output_file.write(packet_header + data)

    def sniff(self) -> None:
        """Start sniffer in while True"""
        raw_socket = socket(AF_PACKET, SOCK_RAW, ntohs(3))
        self.write_global_header()
        while True:
            raw_data = raw_socket.recvfrom(65535)[0]
            if len(raw_data) != 0:
                self.write_packet(raw_data)

    def scan_tcp_session(self) -> None:
        """Start sniffer and the definition of the TCP session and recording
        the session in the PCAP """
        raw_socket = socket(AF_PACKET, SOCK_RAW, ntohs(3))
        unpacker = Unpacker()
        buffer_tcp = []
        count = 1
        temp = "tcp_sessions_"
        while exists(temp + str(count)):
            count += 1
        self.output_dir = temp + str(count) + sep
        mkdir(self.output_dir)
        while True:
            raw_data = raw_socket.recvfrom(65535)[0]
            destination_mac, source_mac, type_protocol, data \
                = unpacker.get_ethernet_head(raw_data)
            if type_protocol == 8:
                ip_version, ip_header_length, ttl, transport_proto, source_ip, \
                target_ip, data = unpacker.get_ipv4_head(data)
                if transport_proto == 6:
                    buffer_tcp.append(raw_data)

            if len(buffer_tcp) > 10:
                self.analyzes_tcp_packets(buffer_tcp.copy())
                buffer_tcp.clear()

    def sniff_and_print(self) -> None:
        """Start sniffer and print in console"""
        s = socket(AF_PACKET, SOCK_RAW, ntohs(3))
        self.write_global_header()
        printer = Printer()
        while True:
            raw_data, addres = s.recvfrom(65535)
            printer.print_packet(raw_data)
            self.write_packet(raw_data)
