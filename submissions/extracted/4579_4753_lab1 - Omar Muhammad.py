# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
from _struct import *
import struct


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.
    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.
    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.
    This class is also responsible for reading/writing files to the
    hard disk.
    Failing to comply with those requirements will invalidate
    your submission.
    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1

    def __init__(self):
        """
        Add and initialize the internal fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)
        return out_packet
        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        opcode = struct.unpack('!H', packet_bytes[0:2])[0]
        if opcode == 5:
            errormsg = packet_bytes[4:]
            print(errormsg)
            sys.exit();
        return packet_bytes
        pass

    def _do_some_logic(self, input_packet):
        opcode = struct.unpack('!H', input_packet[0:2])[0]
        if opcode == 3:
            data = input_packet[4:]
            return data
        pass

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.
        For example;
        s_socket.send(tftp_processor.get_next_output_packet())
        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        len1 = len(file_path_on_server)
        read_request = pack('!H' + str(len1) + 'sB' + '5sB', 1, file_path_on_server.encode("ascii"), 0,
                            "octet".encode("ascii"), 0)

        return read_request

    pass

    def upload_file(self, file_path_on_server):
        len1 = len(file_path_on_server)
        write_request = pack('!H' + str(len1) + 'sB' + '5sB', 2, file_path_on_server.encode("ascii"), 0,
                             "octet".encode("ascii"), 0)
        return write_request

    pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def readchunks(file):
    f = open(file, "rb")
    s = []
    size = os.path.getsize(file)
    y = int(size / 512)
    for x in range(0, y + 1):
        s.append(f.read(512))
    return s


pass


def writechunks(file, s):
    filewrite = open(file, "ab")
    filewrite.write(s)
    filewrite.flush()


def setup_sockets(address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_address = (address, 69)
    client_socket.bind(client_address)
    r_bytes = bytearray([0, 2, 97, 46, 116, 120, 116, 0, 111, 99, 116, 101, 116, 0])
    client_socket.sendto(r_bytes, client_address)


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    tftp_1 = TftpProcessor()
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_address = (address, 69)
        write_request = tftp_1.upload_file(file_name)
        client_socket.sendto(write_request, client_address)
        packet = client_socket.recvfrom(2048)
        data, client_address1 = packet
        tftp_1.process_udp_packet(data, client_address1)
        s = readchunks(file_name)
        for x in range(0, len(s)):
            len_data = len(s[x])
            data_packet = pack('!HH' + str(len_data) + 's', 3, x+1, s[x])
            client_socket.sendto(data_packet, client_address1)
            packet = client_socket.recvfrom(2048)
            data, client_address = packet
            while client_address != client_address1:
                client_socket.sendto(data_packet, client_address1)
                packet = client_socket.recvfrom(2048)
                data, client_address = packet
            tftp_1.process_udp_packet(data, client_address)

        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_address = (address, 69)
        read_request = tftp_1.request_file(file_name)
        client_socket.sendto(read_request, client_address)
        packet = client_socket.recvfrom(2048)
        data, client_address1 = packet
        data1 = tftp_1.process_udp_packet(data, client_address1)
        block_number = 1
        while len(data1) == 512:
            packet = client_socket.recvfrom(2048)
            data, client_address = packet
            while client_address != client_address1:
                packet = client_socket.recvfrom(2048)
                data, client_address = packet
            data1 = tftp_1.process_udp_packet(data, client_address)
            # len1 = len(data1)
            # data2 = unpack(str(len1) +'s', data1)
            writechunks(file_name, data1)
            ack_packet = pack('!HH', 4, block_number)
            block_number += 1
            client_socket.sendto(ack_packet, client_address)

        pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1)
    operation = get_arg(2)
    file_name = get_arg(3)

    # Modify this as needed.

    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()