import socket
import sys
import os
import enum
from struct import *


class TftpProcessor(object):

    class TftpPacketType(enum.Enum):

        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5
    readfile = {}
    y = 0

    def __init__(self):

        self.packet_buffer = []

    def process_udp_packet(self, packet_data, packet_source, filename, i):

        in_packet = self._parse_udp_packet(packet_data, filename, packet_source)
        out_packet = self._do_some_logic(in_packet, i)
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes, filename, packet_source):

        if tt.y == 1:

            print(f"Received a packet from {packet_source}")
        elif tt.y == 0:

            print(f"Sent a packet to {packet_source}")

        original_data1 = unpack('!hh{}s'.format(len(packet_bytes)-4), packet_bytes)
        if original_data1[0] == 3:
            self.file_append(filename, original_data1[2])
            return original_data1[0:2]
        elif original_data1[0] == 4:

            return original_data1[0:2]

        elif original_data1[0] == 5:
            ending = original_data1[2].decode("ASCII")
            exit(ending)

    @staticmethod
    def _do_some_logic(input_packet, i):

        if input_packet[0] == 3:
            qwe = pack('!hh', 4, input_packet[1])
            return qwe

        if input_packet[0] == 4:
            qwe = pack('!hh{}s'.format(len(tt.readfile[i-1])), 3, i, tt.readfile[i-1])
            return qwe

    @staticmethod
    def file_reader(filename):

        f = open(filename, 'r', encoding='utf-8')
        data = f.read()
        f.close()
        data2 = data.encode("ascii")
        tt.readfile = [data2[i:i+512] for i in range(0, len(data2), 512)]

    def get_next_output_packet(self):

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):

        return len(self.packet_buffer) != 0

    @staticmethod
    def request_file(file_path_on_server):

        tt.y = 1
        t = TftpProcessor.TftpPacketType.RRQ.value
        packet = pack('!h{}sb5sb'.format(len(file_path_on_server)), t, file_path_on_server.encode("ascii"),
                      0, "octet".encode("ascii"), 0)
        return packet

    @staticmethod
    def upload_file(file_path_on_server):

        tt.y = 0
        t = TftpProcessor.TftpPacketType.WRQ.value
        packet = pack('!h{}sb5sb'.format(len(file_path_on_server)), t, file_path_on_server.encode("ascii"), 0,
                      "octet".encode("ascii"), 0)
        return packet

    @staticmethod
    def file_intiate(filename):
        open(filename, "w")

    @staticmethod
    def file_append(filename, data):
        points = open(filename, "a")
        points.write(data.decode("ASCII"))
        points.close()


tt = TftpProcessor()


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def termination(server_packet):
    if len(server_packet) < 516:
        exit("Transfer is Completed")


def setup_sockets(address, packet, filename):

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)
    client_socket.bind(('', 5555))
    client_socket.sendto(packet, server_address)
    i = 1
    while 1:
        server_packet, server = client_socket.recvfrom(516)
        tt.process_udp_packet(server_packet, server, filename, i)
        client_socket.sendto(tt.get_next_output_packet(), server)
        if tt.y == 1:
            termination(server_packet)
        if tt.y == 0:
            if i < len(tt.readfile):
                i = i+1
            else:
                print("Transfer is Completed")
                break


def parse_user_input(address, operation, file_name=None):

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        ready_packet = tt.upload_file(file_name)
        tt.file_reader(file_name)
        setup_sockets(address, ready_packet, file_name)

    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        ready_packet = tt.request_file(file_name)
        tt.file_intiate(file_name)
        setup_sockets(address, ready_packet, file_name)


def get_arg(param_index, default=None):

    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The command-line argument #[{param_index}] is missing")
            exit(-1)


def main():

    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    ip_address = get_arg(1, "192.168.1.8")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "hello.txt")

    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
