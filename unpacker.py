from socket import htons
from struct import unpack


class Unpacker:
    def get_ethernet_head(self, raw_data: bytes) -> \
            tuple[str, str, int, bytes]:
        """Getting ethernet header"""
        title_format_ethernet_header = '! 6s 6s H'
        end_ethernet_header = 14
        destination, src, prototype = unpack(title_format_ethernet_header,
                                             raw_data[:end_ethernet_header])
        destination_mac = self.get_mac_addr(destination)
        src_mac = self.get_mac_addr(src)
        proto = htons(prototype)
        data = raw_data[end_ethernet_header:]
        return destination_mac, src_mac, proto, data

    def get_ipv4_head(self, raw_data: bytes) -> \
            tuple[int, int, int, int, str, str, bytes]:
        """Getting ipv4 header"""
        version_header_length = raw_data[0]
        title_format_ipv4_header = '! 8x B B 2x 4s 4s'
        offset_ipv4_version = 4
        end_ipv4_header = 20
        bytes_header_length = 15
        version = version_header_length >> offset_ipv4_version
        header_length = (version_header_length & bytes_header_length) * 4
        ttl, proto, src, target = unpack(title_format_ipv4_header,
                                         raw_data[:end_ipv4_header])
        src = self.get_ip(src)
        target = self.get_ip(target)
        data = raw_data[header_length:]
        return version, header_length, ttl, proto, src, target, data

    def get_ip(self, addr: bytes) -> str:
        """Converting an ip address from bytes to a string"""
        return '.'.join(map(str, addr))

    def get_mac_addr(self, bytes_addr: bytes) -> str:
        """Converting an MAC address from bytes to a string"""
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def get_tcp_head(self, raw_data: bytes) -> \
            tuple[int, int, int, int, int, int, int, int, int, int, bytes]:
        """Getting tcp header"""
        title_format_tcp_header = '! H H L L H'
        end_tcp_header_without_flags = 14
        offset_flags = 12
        offset_all_flags = {'flag_urg': 5, 'flag_ack': 4, 'flag_psh': 3,
                            'flag_rst': 2, 'flag_syn': 1, 'flag_fin': 0}
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = \
            unpack(title_format_tcp_header,
                   raw_data[:end_tcp_header_without_flags])
        offset = (offset_reserved_flags >> offset_flags) * 4
        flag_urg = (offset_reserved_flags & 2 ** offset_all_flags[
            'flag_urg']) >> offset_all_flags['flag_urg']
        flag_ack = (offset_reserved_flags & 2 ** offset_all_flags[
            'flag_ack']) >> offset_all_flags['flag_ack']
        flag_psh = (offset_reserved_flags & 2 ** offset_all_flags[
            'flag_psh']) >> offset_all_flags['flag_psh']
        flag_rst = (offset_reserved_flags & 2 ** offset_all_flags[
            'flag_rst']) >> offset_all_flags['flag_rst']
        flag_syn = (offset_reserved_flags & 2 ** offset_all_flags[
            'flag_syn']) >> offset_all_flags['flag_syn']
        flag_fin = offset_reserved_flags & 2 ** offset_all_flags['flag_fin']
        data = raw_data[offset:]
        return src_port, dest_port, sequence, acknowledgment, flag_urg, \
               flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

    def get_icmp_packet(self, raw_data: bytes) -> tuple[int, int, int, bytes]:
        """Icmp packet parser"""
        title_format_icmp_header = '! B B H'
        end_icmp_header = 4
        icmp_type, code, checksum = unpack(title_format_icmp_header,
                                           raw_data[:end_icmp_header])
        return icmp_type, code, checksum, raw_data[end_icmp_header:]

    def get_udp_head(self, raw_data: bytes) -> tuple[int, int, int, bytes]:
        """Getting udp header"""
        title_format_udp_header = '! H H 2x H'
        end_icmp_header = 8
        src_port, dest_port, size = unpack(title_format_udp_header,
                                           raw_data[:end_icmp_header])
        return src_port, dest_port, size, raw_data[end_icmp_header:]

    def get_tcp_packet(self, raw_data) -> \
            tuple[int, int, int, int, int, int, int, int, int, int, bytes]:
        """Getting TCP packet"""
        destination_mac, source_mac, type_protocol, data \
            = self.get_ethernet_head(raw_data)
        ip_version, ip_header_length, ttl, transport_proto, source_ip, \
        target_ip, data = self.get_ipv4_head(data)
        return self.get_tcp_head(data)
