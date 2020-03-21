import sys
import os
import enum
import struct
import socket


class TftpProcessor(object):
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        self.packet_buffer = []

    def process_udp_packet(self, packet_data, packet_source):
        in_packet = self._parse_udp_packet(packet_data)
        self.packet_buffer.append(in_packet)

    def _parse_udp_packet(self, packet_bytes):
        in_packet = None
        if packet_bytes[0] == self.TftpPacketType.RRQ.value or packet_bytes[0] == self.TftpPacketType.WRQ.value:
            in_packet = struct.pack('!H{}sB5sB'.format(len(packet_bytes[1])), packet_bytes[0], packet_bytes[1],
                                    packet_bytes[2], packet_bytes[3], packet_bytes[4])
        elif packet_bytes[0] == self.TftpPacketType.DATA.value:
            in_packet = struct.pack('!HH{}s'.format(len(packet_bytes[2])), packet_bytes[0], packet_bytes[1], packet_bytes[2])
        elif packet_bytes[0] == self.TftpPacketType.ACK.value:
            in_packet = struct.pack('!HH', packet_bytes[0], packet_bytes[1])
        # elif packet_bytes[0] == self.TftpPacketType.ERROR.value:
        #     in_packet = struct.pack('!HH{}sB'.format(packet_bytes[2]), packet_bytes[0], packet_bytes[1],
        #                             packet_bytes[2], packet_bytes[3])
        return in_packet

    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server, data):
        with open(file_path_on_server, 'wb') as f:
            f.write(data)

    def upload_file(self, file_path_on_server):
        data_array = []
        with open(file_path_on_server, 'rb') as f:
            while True:
                data = f.read(512)
                if not data:
                    break
                data_array.append(data)
        return data_array

def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass

def setup_sockets(address):
    s_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return s_socket

def parse_user_input(address, operation, file_name=None):
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")

def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.

def download_data(tftp_processor, s_socket, address):
    data = b''
    while tftp_processor.has_pending_packets_to_be_sent():
            s_socket.sendto(tftp_processor.get_next_output_packet(), address)
            received_packet, address = s_socket.recvfrom(516)
            if received_packet[1] != 3:
                print('Some Error')
                break
            packet_data = [4, received_packet[3]]
            data += received_packet[4:]
            if len(received_packet) == 516:
                tftp_processor.process_udp_packet(packet_data, address)
    return data
        
def push_data(tftp_processor, address, data_array):
    for i in range(len(data_array)): 
        packet_data = [3, i + 1, data_array[i]]
        tftp_processor.process_udp_packet(packet_data, address)
    
def upload_data(tftp_processor, s_socket, address):
    while tftp_processor.has_pending_packets_to_be_sent():
        s_socket.sendto(tftp_processor.get_next_output_packet(), address)
        received_data, address = s_socket.recvfrom(4)
        if received_data[1] != 4:
            print('Some Error')
            break
    if not tftp_processor.has_pending_packets_to_be_sent():
        print('Uploading Finished')

def initiate_connection(tftp_processor, address, file_name, type):
    if type == 'RRQ':
        packet_data = [1, bytes(file_name, 'ascii'), 0, bytes('octet', 'ascii'), 0]
        tftp_processor.process_udp_packet(packet_data, address)
    elif type == 'WRQ':
        packet_data = [2, bytes(file_name, 'ascii'), 0, bytes('octet', 'ascii'), 0]
        tftp_processor.process_udp_packet(packet_data, address)

def main():
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")
    parse_user_input(ip_address, operation, file_name)

    port = 9069
    address = (ip_address, port)

    s_socket = setup_sockets(address)
    tftp_processor = TftpProcessor()

    if operation == 'pull':
        initiate_connection(tftp_processor, address, file_name, 'RRQ')
        data = download_data(tftp_processor, s_socket, address)
        tftp_processor.request_file('{}/{}'.format(os.getcwd(), file_name), data)
        print('Downloading Finished')
    elif operation == 'push':
        initiate_connection(tftp_processor, address, file_name, 'WRQ')
        data_array = tftp_processor.upload_file(file_name)
        push_data(tftp_processor, address, data_array)
        upload_data(tftp_processor, s_socket, address)

if __name__ == "__main__":
    main()
