# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct

chunk_size = 512
packet_size = 516

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
        op_code = packet_bytes[0:2]
        block_no = packet_bytes[2:4]
        data = packet_bytes[4:]
        pass

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
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
        rrq = bytearray([0,1])
        file_name = file_path_on_server.encode('utf-8')
        zero = bytearray([0])
        octet = "octet".encode('utf-8')
        finalrrq = rrq + file_name + zero + octet + zero
        return finalrrq

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        wrq = bytearray([0,2])
        file_name = file_path_on_server.encode('utf-8')
        zero = bytearray([0])
        octet = "octet".encode('utf-8')
        finalwrq = wrq + file_name + zero + octet + zero
        return finalwrq


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", 69)
    return sock, server_address


def parse_received_packet(packet):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    op_code, block_num = struct.unpack("!HH", packet[0:4])
    if op_code == 3:
        print("Receiving data block")
    elif op_code == 4:
        print("Acknowledge")
    elif op_code == 5:
        print("Error")
        '''
        Value               Meaning
        0       Not defined, see error message (if any).
        1       File not found.
        2       Access violation.
        3       Disk full or allocation exceeded.
        4       Illegal TFTP operation.
        5       Unknown transfer ID.
        6       File already exists.
        7       No such user.

        '''
        if block_num == 0:
            print("Undefined Error : ")
            print(packet[4:])
        elif block_num == 1:
            print("File not found")
        elif block_num == 2:
            print("Access violation")
        elif block_num == 3:
            print("Disk full or allocation exceeded")
        elif block_num == 4:
            print("Illegal TFTP operation")
        elif block_num == 5:
            print("Unknown transfer ID")
        elif block_num == 6:
            print("File already exists")
        elif block_num == 7:
            print("No such user")
        exit(-1)

    return  op_code,block_num

def check_opcode(opcode):
    if opcode == 3:
        return 




def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code. 
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    Tftp = TftpProcessor()
    socket, server_address = setup_sockets(address)
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        wrq = Tftp.upload_file(file_name)
        socket.sendto(wrq,server_address)
        response, packet_source = socket.recvfrom(4096)
        opcode, block_no = parse_received_packet(response)
        if opcode != 4:
            print("Error occured")
            return
        else:
            fileW = open(file_name, "rb")
            num = 0
            while True:
                readData = fileW.read(chunk_size)
                sendData = struct.pack("!HH" ,3 , num) + readData
                socket.sendto(sendData, packet_source)
                recv = socket.recvfrom(1024)
                op_code, block_num = struct.unpack("!HH", recv[0][:4]) 
                if len(sendData) == packet_size and op_code == 4 and block_num == num:
                    num += 1
                else:
                    print("Upload success")
                    break
        fileW.close()
        socket.close()
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        rrq = Tftp.request_file(file_name)
        socket.sendto(rrq,server_address)
        fileR = open(file_name, "ab")
        while True:
            response, packet_source = socket.recvfrom(4096)
            opcode, block_no = parse_received_packet(response)
            if opcode == 3:
                ACK = struct.pack("!HH", 4, block_no)
                socket.sendto(ACK, (packet_source[0], packet_source[1]))
            if opcode == 5:
                print("File doesn't exist")
                break
            fileR.write(response[4:])
            if len(response) < packet_size:
                print("Download complete")
                break
        fileR.close()
        socket.close()
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
