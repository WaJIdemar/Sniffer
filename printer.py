from textwrap import wrap
from unpacker import Unpacker


class Printer:
    TAB_1 = '\t - '
    TAB_2 = '\t\t - '
    TAB_3 = '\t\t\t - '
    TAB_4 = '\t\t\t\t - '

    DATA_TAB_1 = '\t '
    DATA_TAB_2 = '\t\t '
    DATA_TAB_3 = '\t\t\t '
    DATA_TAB_4 = '\t\t\t\t '

    def print_udp_packet(self, src_port: int, dest_port: int, size: int,
                         data: bytes) -> None:
        """Print UDP packet in console"""
        print(self.TAB_1 + 'UDP Segment:')
        print(
            self.TAB_2 + f'Source Port: {src_port}, '
                         f'Destination Port: {dest_port}, Length: {size}')
        print(self.format_multi_line(self.DATA_TAB_3, data))

    def print_ethernet_header(self, destination_mac: str, source_mac: str,
                              type_protocol: int) -> None:
        """Print Ethernet Header in console"""
        print('\nEthernet Frame:')
        print(
            f'Destination: {destination_mac}, Source: {source_mac}, '
            f'Protocol: {type_protocol} ')

    def print_ipv4_header(self, ip_version: int, ip_header_length: int,
                          ttl: int, transport_proto: int, source_ip: str,
                          target_ip: str) -> None:
        """Print IPv4 Header in console"""
        print(self.TAB_1 + 'IPv4 Packet:')
        print(
            self.TAB_2 + f'Version: {ip_version}, '
                         f'Header Length: {ip_header_length}, TTL: {ttl}')
        print(
            self.TAB_2 + f'Protocol: {transport_proto}, Source: {source_ip}, '
                         f'Target: {target_ip}')

    def print_icmp_header(self, icmp_type: int, code: int,
                          checksum: int, data: bytes) -> None:
        """Print ICMP Header in console"""
        print(self.TAB_1 + 'ICMP Packet:')
        print(
            self.TAB_2 + f'Type{icmp_type}, Code: {code}, '
                         f'Checksum: {checksum},')
        print(self.TAB_2 + 'Data:')
        print(self.format_multi_line(self.DATA_TAB_3, data))

    def print_tcp_packet(self, source_port: int, destination_port: int,
                         sequence: int, acknowledgment: int, flag_urg: int,
                         flag_ack: int, flag_psh: int, flag_rst: int,
                         flag_syn: int, flag_fin: int, data: bytes) -> None:
        """Print TCP packet in console"""
        print(self.TAB_1 + 'TCP Segment:')
        print(
            self.TAB_2 + f'Source Port: {source_port}, '
                         f'Destination Port: {destination_port}')
        print(
            self.TAB_2 + f'Sequence: {sequence}, '
                         f'Acknowledgment: {acknowledgment}')
        print(self.TAB_2 + 'Flags:')
        print(
            self.TAB_3 + f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}')
        print(
            self.TAB_3 + f'RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
        if len(data) > 0:
            try:
                http = data.decode('utf-8')
                print(self.TAB_2 + 'HTTP Data:')
                for line in http.split('\n'):
                    print(self.DATA_TAB_3 + line)
            except UnicodeDecodeError:
                print(self.TAB_2 + 'TCP Data:')
                print(self.format_multi_line(self.DATA_TAB_3, data))

    def print_packet(self, raw_data: bytes) -> None:
        """Print packet in console"""
        unpacker = Unpacker()
        destination_mac, source_mac, type_protocol, data \
            = unpacker.get_ethernet_head(raw_data)
        self.print_ethernet_header(destination_mac, source_mac, type_protocol)
        if type_protocol == 8:
            ip_version, ip_header_length, ttl, transport_proto, source_ip, \
            target_ip, data = unpacker.get_ipv4_head(data)
            self.print_ipv4_header(ip_version, ip_header_length, ttl,
                                   transport_proto, source_ip, target_ip)
            if transport_proto == 1:
                icmp_type, code, checksum, data = unpacker.get_icmp_packet(
                    data)
                self.print_icmp_header(icmp_type, code, checksum, data)

            elif transport_proto == 6:
                source_port, destination_port, sequence, acknowledgment, \
                flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
                data = unpacker.get_tcp_head(
                    data)
                self.print_tcp_packet(source_port, destination_port, sequence,
                                      acknowledgment, flag_urg, flag_ack,
                                      flag_psh, flag_rst, flag_syn, flag_fin,
                                      data)

            elif transport_proto == 17:
                src_port, dest_port, size, data = unpacker.get_udp_head(data)
                self.print_udp_packet(src_port, dest_port, size, data)

    def format_multi_line(self, prefix: str, string: bytes,
                          size: int = 80) -> str:
        """Formats byte strings for easy output to the console"""
        size -= len(prefix)

        string = ''.join(r'\x{:02}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
        return '\n'.join(
            [prefix + line for line in wrap(string, size)])
