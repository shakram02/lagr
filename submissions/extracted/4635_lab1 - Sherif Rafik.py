# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct
import shutil

BUFFER_SIZE = 2048

TOTAL, USED, FREE = shutil.disk_usage("/")


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

    ERROR_MSG = {
        0: "Not defined, see error message.", # Used
        1: "File not found.",  # Used
        2: "Access violation.",
        3: "Disk full or allocation exceeded.",  # Used
        4: "Illegal TFTP operation.",  # Used
        5: "Unknown transfer ID.",
        6: "File already exists.", # Used
        7: "No such user."
    }

    def __init__(self):
        self.packet_buffer = []
        self.mode = "octet"
        self.upload = None
        self.is_done = False
        self.file = None
        self.DEFAULT_BLOCK_SIZE = 516
        self.DEFAULT_DATA_SIZE = 512
        self.current_block_count = 1

    def _open_file(self, file_name):
        if self.upload:
            # Check if the file the client wants to upload doesn't exist
            if os.path.isfile(file_name):
                self.file = open(file_name, "rb")
            else:
                error_code = 1
                print(str(error_code) + " : " + self.ERROR_MSG[error_code])
                sys.exit(error_code)
        else:
            # Check if the file the client wants to download already exits
            if not os.path.isfile(file_name):
                self.file = open(file_name, "wb")
            else:
                error_code = 6
                print(str(error_code) + " : " + self.ERROR_MSG[error_code])
                sys.exit(error_code)

    def process_udp_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")
        output_packet = self._parse_udp_packet(packet_data)

        # This shouldn't change.
        self.packet_buffer.append(output_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        # Extract the opcode from the packet received and act accordingly
        opcode = self._get_opcode(packet_bytes)
        if opcode == self.TftpPacketType.DATA.value:
            return self._process_data_packets(packet_bytes)
        elif opcode == self.TftpPacketType.ACK.value:
            return self._process_ack_packets(packet_bytes)
        elif opcode == self.TftpPacketType.ERROR.value:
            return self._process_error_packets(packet_bytes)
        else:
            error_code = 4
            return self._make_error_packet(error_code)

    def _process_data_packets(self, packet):
        """
            2 bytes     2 bytes      n bytes
            ----------------------------------
            | Opcode |   Block #  |   Data    |
            ----------------------------------
        """
        # Extract the data from the input packet 
        data = self._get_data(packet)
        block_number = self._get_block_number(packet)

        if block_number != self.current_block_count:
            error_code = 4
            output_packet = self._make_error_packet(error_code)
            return output_packet

        # Check if the disk is full
        if USED + len(data) > TOTAL:
            error_code = 3
            output_packet = self._make_error_packet(error_code)
            return output_packet

        # Write the extracted data to the file
        self.file.write(data)
        # Check if this packet is the last one
        if len(packet) < self.DEFAULT_BLOCK_SIZE:
            self.is_done = True
            self.file.close()

        self.current_block_count += 1
        # After receiving a DATA packet we create an ACK packet
        output_packet = self._make_ack_packet(block_number)
        return output_packet

    def _process_ack_packets(self, packet):
        """
            2 bytes     2 bytes
            ---------------------
           | Opcode |   Block #  |
            ---------------------
        """
        # Extract the block number from the input packet
        block_number = self._get_block_number(packet)

        if block_number != self.current_block_count - 1:
            error_code = 4
            output_packet = self._make_error_packet(error_code)
            return output_packet

        # After receiving an ACK packet we create a DATA packet
        data = self.file.read(self.DEFAULT_DATA_SIZE)
        
        if len(data) < self.DEFAULT_DATA_SIZE:
            self.is_done = True

        self.current_block_count += 1
        output_packet = self._make_data_packet(block_number + 1, data)
        return output_packet

    def _process_error_packets(self, packet):
        """
            2 bytes     2 bytes      string    1 byte
            -----------------------------------------
            | Opcode |  ErrorCode |   ErrMsg   |   0 |
            -----------------------------------------
        """
        error_code = struct.unpack("!H", packet[2:4])[0]
        print(str(error_code) + " : " + self.ERROR_MSG[error_code])
        sys.exit(error_code)

    def _make_request_packet(self, opcode, file_name):
        """
            Create the WRQ or RRQ according to the user input
            2 bytes     string    1 byte     string   1 byte
            ------------------------------------------------
           | Opcode |  Filename  |   0  |    Mode    |   0  |
            ------------------------------------------------
        """
        values = (opcode, file_name.encode("ASCII"), 0, self.mode.encode("ASCII"), 0)
        s = struct.Struct('!H{}sB{}sB'.format(len(file_name), len(self.mode)))
        return s.pack(*values)

    def _make_ack_packet(self, block_num):
        """
            Create the acknowledge packet
            2 bytes     2 bytes
            ---------------------
           | Opcode |   Block #  |
            ---------------------
        """
        ack_packet = struct.pack("!HH", self.TftpPacketType.ACK.value, block_num)
        return ack_packet

    def _make_data_packet(self, block_num, data):
        """
            Create the data packet
            2 bytes     2 bytes      n bytes
            ----------------------------------
            | Opcode |   Block #  |   Data     |
            ----------------------------------
        """
        data_packet = struct.pack("!HH{}s".format(len(data)), self.TftpPacketType.DATA.value, block_num, data)
        return data_packet

    def _make_error_packet(self, error_code):
        """
            Create the error packet
            2 bytes     2 bytes      string    1 byte
            -----------------------------------------
            | Opcode |  ErrorCode |   ErrMsg   |   0  |
            -----------------------------------------
        """
        error_packet = struct.pack("!HH{}sB".format(len(self.ERROR_MSG[error_code])), self.TftpPacketType.ERROR.value, error_code, self.ERROR_MSG[error_code].encode("ASCII"), 0)
        return error_packet

    def _get_opcode(self, packet):
        # Extract the opcode field from the packet
        return struct.unpack("!H", packet[:2])[0]

    def _get_block_number(self, packet):
        # Extract the block number field from the packet
        # unpack returns a tuple, so we add [0]
        return struct.unpack("!H", packet[2:4])[0]

    def _get_data(self, packet):
        # Extract the data field from the packet
        return struct.unpack("!{}s".format(len(packet) - 4), packet[4:])[0]

    def _get_error_code(self, packet):
        # Extract the error code from the packet
        return struct.unpack("!H", packet[2:4])[0]

    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        packet = self._make_request_packet(self.TftpPacketType.RRQ.value, file_path_on_server)
        return packet

    def upload_file(self, file_path_on_server):
        packet = self._make_request_packet(self.TftpPacketType.WRQ.value, file_path_on_server)
        return packet


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)

    return client_socket, server_address


def send_packet(packet, client_socket, server_address):
    # Send packet to remote server
    client_socket.sendto(packet, server_address)


def receive_packet(client_socket, buffer_size):
    # Receive a packet
    packet, address = client_socket.recvfrom(buffer_size)
    return packet, address


def parse_user_input(tftp, address, operation, file_name=None):
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        tftp.upload = True
        packet = tftp.upload_file(file_name)
        return packet
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        tftp.upload = False
        packet = tftp.request_file(file_name)
        return packet
    else:
        error_code = 4
        print(str(error_code) + " : " + tftp.ERROR_MSG[error_code])
        sys.exit(error_code)


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
            exit(-1)  # Program execution failed.


def tftp_logic(tftp, packet, client_socket, server_address):
    # Send the first packet according to the user input, WRQ or RRQ
    send_packet(packet, client_socket, server_address)

    while not tftp.is_done:
        # receive packet from the server (ack / data)
        input_packet, address = receive_packet(client_socket, BUFFER_SIZE)
        # Create a new packet according to the packet received from the server
        tftp.process_udp_packet(input_packet, address)
        output_packet = tftp.get_next_output_packet()
        # Check if the output packet is not none and send it 
        # None if no more packets needs to be send
        send_packet(output_packet, client_socket, address)
        '''
        Check if the output_packet is an error packet
        and if so terminate the connection because the server (tftp software)
        doesn't terminate on its own 
        '''
        opcode = tftp._get_opcode(output_packet)
        if opcode == tftp.TftpPacketType.ERROR.value:
            error_code = tftp._get_error_code(output_packet)
            print(str(error_code) + " : " + tftp.ERROR_MSG[error_code])
            sys.exit(error_code)

    if tftp.upload:
        # To make sure the last ack packet is received
        input_packet, address = receive_packet(client_socket, BUFFER_SIZE)       
    
    tftp.file.close()
    print(address, server_address)


def main():
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

    # Create a new instance of the Tftp processor
    tftp = TftpProcessor()

    # Setup the socket 
    client_socket, server_address = setup_sockets(ip_address)

    # Get the first packet according to the user input.
    packet = parse_user_input(tftp, ip_address, operation, file_name)

    # Open the file according to the user input (Reading or Writing)
    tftp._open_file(file_name)

    # Call the main method
    tftp_logic(tftp, packet, client_socket, server_address)
    

if __name__ == "__main__":
    main()
