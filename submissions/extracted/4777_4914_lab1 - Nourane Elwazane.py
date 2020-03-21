# Don't forget to change this file's name before submission.
import fnmatch
import socket
import sys
import os
import enum
from _struct import *

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
total_number_of_blocks = 0
exit_code = False
global_file_name = ''
global_last_packet_sent=''
global_operation = ''

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
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.file_array = ''
        self.block_number = 0
        self.last_block = False
        self.server_address = ('localhost', 69)
        self.packet_buffer = []
        self.data_packets = []
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
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        global global_last_packet_sent
        global_last_packet_sent = out_packet

        # This shouldn't change.
        self.packet_buffer.append(out_packet)
        pass

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        packet_type = int.from_bytes(packet_bytes[0:2], 'big')

        if packet_type == 3:
            return 3, self.check_DATA_packet(packet_bytes[2:])
        elif packet_type == 4:
            return 4, self.check_ACK_packet(packet_bytes[2:])
        elif packet_type == 5:
            self.check_ERROR_packet(packet_bytes[2:])
            exit()
        pass

    def check_ERROR_packet(self, packed_packet):
        error_message=packed_packet[2:len(packed_packet)-2].decode('ascii')
        print(f'ERROR : {error_message}')
        close_socket()
        pass

    def check_DATA_packet(self, packed_packet):
        if len(packed_packet) <= 514:
            if int.from_bytes(packed_packet[0:2], 'big') == self.block_number:
                print(f'rcvd blk {self.block_number}')
                self.data_packets.append(packed_packet[2:])
                self.write_downloaded_file()
                print(self.data_packets)
                if len(packed_packet) < 514:
                    self.last_block = True
                    global exit_code
                    exit_code= True
                    print('last blk')
                print()
                return True
            else:
                # print('Illegal TFTP Operation')
                #close_socket()
                return False
        else:
            # print('Illegal TFTP Operation')
            #close_socket()
            return False

    def check_ACK_packet(self, packed_packet):
        if len(packed_packet) == 2:
            if int.from_bytes(packed_packet, 'big') == self.block_number:
                print(f'rcvd {self.block_number} blk')
                if self.block_number == total_number_of_blocks:
                    print('Last Block Sent To Server')
                    close_socket()
                print()
                return True
        else:
            print('Illegal TFTP Operation')
            #close_socket()
            return False

    def acceptable_packet_type(self, packet_type):
        if packet_type == 5: #mesh 7ay3ady 3aleha
            return True
        if global_operation == 'pull':
            if packet_type == 3:
                return True
        else:
            if packet_type == 4:
                return True
        return False

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        if input_packet == (3, True):
            if not self.acceptable_packet_type(3):
                return global_last_packet_sent
            message2 = self.send_acknowledgement()
            self.block_number += 1
            return message2
        elif input_packet == (4, True):
            if not self.acceptable_packet_type(4):
                return global_last_packet_sent
            self.block_number += 1
            return self.data_packets.pop(0)
        else:
            return global_last_packet_sent
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
        return len(self.data_packets) != 0

    def create_data_packets(self, input_file):
        CHUNK_SIZE = 512
        chunk = ''
        if os.path.isfile(input_file) is False:
            print("File to be uploaded not found")
            close_socket()
        with open(input_file, 'rb') as infile:
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk: break
                # create packet
                data_block = bytearray()
                data_block += b'\x00\x03'
                self.block_number += 1
                data_block += self.block_number.to_bytes(2, byteorder='big')
                data_block += chunk
                # print(data_block)
                self.data_packets.append(data_block)
        infile.close()
        global total_number_of_blocks
        total_number_of_blocks = self.block_number
        self.block_number = 0
        print('total_number_of_blocks')
        print(total_number_of_blocks)
        pass

    def request_file(self, file_path_on_server):  # 7:20
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        Packet = bytearray()
        Packet += b'\x00\x01'
        Packet += bytearray(file_path_on_server, 'ascii')
        Packet += b'\x00'
        Packet += bytearray('octet', 'ascii')
        Packet += b'\x00'
        print(Packet)
        return list(Packet)

    def create_downloaded_file(self):
        newFile = open(global_file_name, "wb")
        newFile.close()
        pass

    def write_downloaded_file(self):
        newFile = open(global_file_name, "ab")
        while self.has_pending_packets_to_be_sent():
            newFile.write(self.data_packets.pop(0))
        newFile.close()
        pass

    def send_acknowledgement(self):
        ack_packet = b'\x00\x04' + self.block_number.to_bytes(2, byteorder='big')
        return ack_packet

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        Packet = bytearray()
        Packet += b'\x00\x02'
        Packet += bytearray(file_path_on_server, 'ascii')
        Packet += b'\x00'
        Packet += bytearray('octet', 'ascii')
        Packet += b'\x00'
        print(Packet)
        Packed_Packet = pack("!%ds" % (len(Packet)), Packet)
        print(list(Packed_Packet))
        print(unpack("!%ds" % (len(Packet)), Packet))
        return list(Packed_Packet)


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(message, server_address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """

    # message = b'This is the message.  It will be repeated.'

    try:

        # Send data
        print('sending {!r}'.format(message))
        sent = sock.sendto(bytes(message), server_address)
        global exit_code
        if exit_code:
            close_socket()
        # Receive response
        print('waiting to receive')
        data, server = sock.recvfrom(4096)
        print('received {!r}'.format(data))
    finally:
        print()
    return data, server


def close_socket ():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    sock.close()
    print()
    print('closing socket')
    sys.exit()
    pass


def parse_user_input(address, operation, file_name):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    t = TftpProcessor()
    t.file_name=file_name
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        push_file(file_name)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        pull_file(file_name)
        pass


def pull_file(file_name):
    # send RRQ
    t = TftpProcessor()
    t.block_number = 1
    message = setup_sockets(t.request_file(file_name), t.server_address)
    t.server_address = message[1]
    t.create_downloaded_file()
    t.process_udp_packet(message[0], message[1])
    message2=setup_sockets(t.get_next_output_packet(),t.server_address)
    while not t.last_block:
        t.process_udp_packet(message2[0], message2[1])
        message2 = setup_sockets(t.get_next_output_packet(), t.server_address)
    # will return packet to be sent to server
    print(t.server_address)

    pass

def push_file(file_name):
    # send RRQ
    t = TftpProcessor()
    t.create_data_packets(file_name)
    message = setup_sockets(t.upload_file(file_name), t.server_address)
    t.server_address = message[1]
    t.process_udp_packet(message[0], message[1])
    t.block_number = 1
    message2 = setup_sockets(t.get_next_output_packet(),t.server_address)
    while True:
        t.process_udp_packet(message2[0], message2[1])
        message2 = setup_sockets(t.get_next_output_packet(), t.server_address)
    # will return packet to be sent to server
    print(t.server_address)

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
    ip_address = get_arg(1, "127.0.0.1")  # in case not inputed by user
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    if ip_address != '127.0.0.1':
        print()
        print('Invalid IP address !')
        sys.exit()

    t = TftpProcessor()
    global global_file_name
    global_file_name = file_name

    global global_operation
    global_operation = operation

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)

if __name__ == "__main__":
    main()
