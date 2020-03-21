# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct
from struct import *



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
        self.packet_buffer = []
        self.blocks = []
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

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """

        in_packet = [-1,-1,-1]
        opcode = struct.unpack('>H', packet_bytes[0:2])
        opcode = int(opcode[0])

        if opcode == 1: #case RRQ
            in_packet[0] = 1
            return in_packet

        elif opcode == 2: #case WRQ
            in_packet[0] = 2
            return in_packet

        elif opcode == 3: #case DATA
            block_number = struct.unpack('>H', packet_bytes[2:4])
            block_number = int(block_number[0])
            self.blocks.append(packet_bytes[4:len(packet_bytes)])
            in_packet[0] = 3
            in_packet[1] = block_number
            return in_packet

        elif opcode == 4: #case ACK
            block_number = struct.unpack('>H', packet_bytes[2:4])
            block_number = int(block_number[0])
            in_packet[0] = 4
            in_packet[1] = block_number
            return in_packet
        elif opcode == 5: #case ERROR
            error_code = struct.unpack('>H', packet_bytes[2:4])
            error_code = int(error_code[0])
            error_msg = packet_bytes[4:len(packet_bytes)-1].decode()
            in_packet[0] = 5
            in_packet[1] = -1
            in_packet[2] = error_code
            print(error_msg)
            exit()

        else:
            print("UNDEFINED")
            return in_packet

        pass

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        case = input_packet[0]

        if case == 4: #case of uploading FORM DATA PACKET
            opcode = 3
            opcode = opcode.to_bytes(2, 'big')
            block_number = input_packet[1]
            data = self.blocks[block_number]
            block_number +=1
            block_number = block_number.to_bytes(2, 'big')
            out_packet = opcode
            out_packet += block_number
            out_packet += data
            return out_packet

        elif case == 3: #case of downloading FORM ACK PACKET
            opcode = 4
            opcode = opcode.to_bytes(2, 'big')
            block_number = input_packet[1]
            block_number = block_number.to_bytes(2, 'big')
            out_packet = opcode + block_number
            return out_packet
        else:
            opcode = 5
            opcode = opcode.to_bytes(2, 'big')
            error_code = 0
            error_code = error_code.to_bytes(2, 'big')
            error_msg = "UNKNOWN PACKET RECIEVED"
            error_msg = bytes(error_msg, 'ASCII')
            term = '\0'
            term = bytes(term, 'ASCII')
            out_packet = opcode + error_code + error_msg + term
            print(out_packet)
            return out_packet


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
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        file = open(file_path_on_server, 'wb')
        for chunk in self.blocks:
             file.write(chunk)
        pass

        pass

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        file = open(file_path_on_server, 'rb')
        while True:
            block = file.read(512)
            if not block:
                break
            self.blocks.append(block)
        pass



def check_file_name():
    script_name = os.path.basename(__file__)
    print(script_name)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets():
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('localhost', 69)
    return  client_socket,server_address
    pass


def do_socket_logic(case,file_name,client_socket,server_address):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    obj = TftpProcessor()
    client_socket.settimeout(10)
    flag = 0
    if case == 1: #case of uploading
        obj.upload_file(file_name)
        WRQ = initiateWRQ(file_name)
        client_socket.sendto(WRQ, server_address)
        while True:
            timedOut = 0
            for i in range(0,5):
                try:
                    packet_data, packet_source = client_socket.recvfrom(4754)
                    while not server_address == packet_source and flag == 1:
                        print("wrong TID")
                        packet_data, packet_source = client_socket.recvfrom(4754)
                    break
                except socket.timeout as e:
                    print(e)
                    timedOut = 1
            if timedOut == 1:
                exit()
            else:
                server_address = packet_source
                obj.process_udp_packet(packet_data, packet_source)
                packet_to_send = obj.get_next_output_packet()
                client_socket.sendto(packet_to_send, server_address)
                flag = 1
                if len(packet_to_send) < 516:
                    break

    elif case ==2:
        RRQ = initiateRRQ(file_name)
        client_socket.sendto(RRQ, server_address)
        while True:
            timedOut = 0
            for i in range(0, 5):
                try:
                    packet_data, packet_source = client_socket.recvfrom(4754)
                    while not server_address == packet_source and flag == 1:
                        print("wrong TID")
                        packet_data, packet_source = client_socket.recvfrom(4754)
                    break
                except socket.timeout as e:
                    print(e)
                    timedOut = 1
            if timedOut == 1:
                exit()
            else:
                server_address = packet_source
                obj.process_udp_packet(packet_data, packet_source)
                packet_to_send = obj.get_next_output_packet()
                client_socket.sendto(packet_to_send, server_address)
                flag = 1
                if len(obj.blocks[len(obj.blocks) - 1]) < 512:
                    break
        obj.request_file(file_name)




def initiateWRQ(filename):

    opcode = 2
    opcode = opcode.to_bytes(2, 'big')
    fname = bytes(filename, 'ASCII')
    term = '\0'
    term = bytes(term, 'ASCII')
    mode = "octet"
    mode = bytes(mode, "ASCII")
    packet = opcode + fname + term + mode + term
    return packet



def initiateRRQ(filename):
    opcode = 1
    opcode = opcode.to_bytes(2, 'big')
    fname = bytes(filename, 'ASCII')
    term = '\0'
    term = bytes(term, 'ASCII')
    mode = "octet"
    mode = bytes(mode, "ASCII")
    packet = opcode + fname + term + mode + term
    return packet


def parse_user_input(address, operation, file_name=None):

    client_socket,server_address = setup_sockets()

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        do_socket_logic(1,file_name,client_socket,server_address)
        pass

    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        do_socket_logic(2, file_name, client_socket, server_address)
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
            print(f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
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
