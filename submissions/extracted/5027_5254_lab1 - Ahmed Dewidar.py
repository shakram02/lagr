# Don't forget to change this file's name before submission.
import sys
import os
import socket
import struct
from enum import Enum
from collections import namedtuple


class TftpProcessor(object):
    """
    Implements logic for a TFTP server.
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
    class TftpPacketType(Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    Packet = namedtuple('Packet', ['opcode', 'block', 'data'])

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.operation = None
        self.file_obj = None
        self.block = 1

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
        out_packet = self._process_packet(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        return self.Packet(*struct.unpack('!HH', packet_bytes[:4]), packet_bytes[4:])

    """
    Close file and exit for a fatal error.
    """

    def error(self, err):
        if self.file_obj != None:
            self.file_obj.close()
        raise err

    def has_more_data(self):
        return self.operation != None

    def _process_packet(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        if input_packet.opcode == self.TftpPacketType.ERROR.value:
            # Ignore null byte at the end
            self.error(Exception(
                f"Server Error ({input_packet.block}): {input_packet.data[:-1].decode(encoding='ascii')}"))
        if self.operation == "pull":
            if input_packet.opcode != self.TftpPacketType.DATA.value:
                illegal_operation = "Illegal TFTP operation."
                return struct.pack(f'!HH{len(illegal_operation)}sx', self.TftpPacketType.ERROR.value, b'\x00\x04',
                                   illegal_operation.encode(encoding='ascii'))
                # self.error(Exception("Response Error: DATA response expected"))
            if self.block != input_packet.block:
                # Non-matching block, ignore.
                self.error(
                    Warning("Response Warning: Non-matching block number. Ignoring."))
            if self.file_obj == None:
                self.file_obj = open(self.file_name, "wb")
            self.file_obj.write(input_packet.data)
            self.block += 1
            if len(input_packet.data) < 512:
                self.operation = None
            return struct.pack('!HH', self.TftpPacketType.ACK.value, input_packet.block)
        if self.operation == "push":
            if input_packet.opcode != self.TftpPacketType.ACK.value:
                self.error(Exception("Response Error: ACK response expected"))
            if self.block != input_packet.block:
                # Non-matching block, ignore.
                self.error(
                    Warning("Response Warning: Non-matching block number. Ignoring."))
            if self.file_obj == None:
                self.file_obj = open(self.file_name, "rb")
            data_block = self.file_obj.read(512)
            if len(data_block) < 512:
                self.operation = None
            self.block += 1
            return struct.pack(f"!HH{len(data_block)}s", self.TftpPacketType.DATA.value, self.block, data_block)

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
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        self.operation = "pull"
        self.file_name = file_path_on_server
        self.packet_buffer.append(struct.pack(
            f"!H{len(file_path_on_server)}sx{len('octet')}sx",
            self.TftpPacketType.RRQ.value,
            file_path_on_server.encode(encoding='ascii'),
            b'octet'
        ))

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        self.operation = "push"
        self.file_name = file_path_on_server
        self.block = 0
        self.packet_buffer.append(struct.pack(
            f"!H{len(file_path_on_server)}sx{len('octet')}sx",
            self.TftpPacketType.WRQ.value,
            file_path_on_server.encode(encoding='ascii'),
            b'octet'
        ))


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    processor = TftpProcessor()
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        processor.upload_file(file_name)
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        processor.request_file(file_name)
    else:
        print(f"[FATAL] Invalid operation: {operation}")
        exit(-1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        address = (address, 69)
        while processor.has_pending_packets_to_be_sent():
            try:
                s.sendto(processor.get_next_output_packet(), address)
                if processor.has_more_data():
                    data, address = s.recvfrom(
                        516 if operation == "pull" else 4)
                    processor.process_udp_packet(data, address)
            except Warning as e:
                print(f"[WARN] {e.args}")
            except Exception as e:
                print(f"[FATAL] {e.args}")
                exit(-1)


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
            exit(-1)    # Program execution failed.


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
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
