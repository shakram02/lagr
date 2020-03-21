import sys
import os
import enum
import socket
import struct


class TftpProcessor(object):
    """
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.

    The class' input and outputs are byte arrays only.

    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.

    This class is also responsible for reading/writing files to the
    hard disk.
    """

    class TftpPacketType(enum.Enum):
        # Represents the TFTP packet types.
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    class TftpErrorCodes:
        # Represents the TFTP error codes.
        NOT_DEFINED = 0
        FILE_NOT_FOUND = 1
        ACCESS_VIOLATION = 2
        DISK_FULL = 3
        ILLEGAL_TFTP = 4
        UNKNOWN_ID = 5
        FILE_ALREADY_EXISTS = 6
        NO_SUCH_USER = 7

        ERROR_CODES = {
            NOT_DEFINED: "Not defined",
            FILE_NOT_FOUND: "File not found",
            ACCESS_VIOLATION: "Access violation",
            DISK_FULL: "Disk full or allocation exceeded",
            ILLEGAL_TFTP: "Illegal TFTP operation",
            UNKNOWN_ID: "Unknown transfer ID",
            FILE_ALREADY_EXISTS: "File already exists",
            NO_SUCH_USER: "No such user"
        }

    def __init__(self):
        self.HEADER_SIZE = 4
        self.PACKET_SIZE = 512
        self.MODE = "octet"
        self.file_name = None
        self.expected_block_num = None
        self.is_done = False
        self.is_RRQ = False
        self.is_error = False
        self.packet_buffer = []
        self.data_buffer = []

    def process_udp_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")
        out_packet = self._parse_udp_packet(packet_data)

        self.packet_buffer.append(out_packet)

        return out_packet

    def _parse_udp_packet(self, packet_bytes):
        packet_list = list(packet_bytes)

        # Return in case of a faulty packet
        if len(packet_list) < self.HEADER_SIZE:
            self.is_error = True
            return self._get_error_packet(self.TftpErrorCodes.ILLEGAL_TFTP)

        # Extract header and packet data from the TFTP packet.
        header, packet = packet_list[:self.HEADER_SIZE], packet_list[self.HEADER_SIZE:]
        packet_type, block_num = struct.unpack("!HH", bytearray(header))

        if packet_type == self.TftpPacketType.DATA.value:
            # Return if a wrong block number was sent
            if block_num != self.expected_block_num:
                self.is_error = True
                return self._get_error_packet(self.TftpErrorCodes.ILLEGAL_TFTP)
            # Return acknowledgement to the server.
            return self._pull_packet(packet, block_num)
        elif packet_type == self.TftpPacketType.ACK.value:
            # Return if a wrong block number was sent
            if block_num != self.expected_block_num:
                self.is_error = True
                return self._get_error_packet(self.TftpErrorCodes.ILLEGAL_TFTP)
            # Return data packet to the server.
            return self._push_packet(block_num)
        elif packet_type == self.TftpPacketType.ERROR.value:
            # Display error and terminate the connection.
            err_size = len(packet_list) - 5
            error = struct.unpack(f"!{err_size}sx", bytearray(packet))[0]
            print("[SERVER ERROR]", error.decode("ascii"))
            return
        else:
            # Return error packet to the server.
            self.is_error = True
            return self._get_error_packet(self.TftpErrorCodes.ILLEGAL_TFTP)

    def _pull_packet(self, packet, block_num):
        """
        INPUT
                  2 Bytes  2 Bytes   n Bytes
                  ╔══════╦═════════╦════════╗
        DATA      ║  03  ║ Block # ║  DATA  ║
                  ╚══════╩═════════╩════════╝
        OUTPUT
                  2 Bytes  2 Bytes
                  ╔══════╦═════════╗
        ACK       ║  04  ║ Block # ║
                  ╚══════╩═════════╝
        """
        # Generate the ACK packet to be sent to the server using the format illustrated.
        self.expected_block_num += 1
        self.data_buffer.append(packet)
        if len(packet) < self.PACKET_SIZE:
            self.is_done = True
            is_written = self._write_to_file(os.path.dirname(os.path.realpath(__file__)) + "/" + self.file_name)
            if not is_written:
                return self._get_error_packet(self.TftpErrorCodes.DISK_FULL)
        response = struct.pack("!HH", self.TftpPacketType.ACK.value, block_num)
        return response

    def _push_packet(self, block_num):
        """
        INPUT
                  2 Bytes  2 Bytes
                  ╔══════╦═════════╗
        ACK       ║  04  ║ Block # ║
                  ╚══════╩═════════╝
        OUTPUT
                  2 Bytes  2 Bytes   n Bytes
                  ╔══════╦═════════╦════════╗
        DATA      ║  03  ║ Block # ║  DATA  ║
                  ╚══════╩═════════╩════════╝
        """
        # Generate the DATA packet to be uploaded using the format illustrated.
        if block_num == 0:
            self._read_from_file(self.file_name)
        self.expected_block_num += 1
        if self._has_pending_packets_to_be_written():
            next_packet = self._get_next_data_packet()
        else:
            next_packet = []
        size = len(next_packet)
        if size < self.PACKET_SIZE:
            self.is_done = True
        response = struct.pack(f"!HH{size}s", self.TftpPacketType.DATA.value, block_num + 1, bytearray(next_packet))
        return response

    def get_next_output_packet(self):
        # Returns the next packet that needs to be sent.
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        # Returns if any packets to be sent are available.
        return len(self.packet_buffer) != 0

    def _get_next_data_packet(self):
        # Returns the next data packet that needs to be stored to disk.
        return self.data_buffer.pop(0)

    def _has_pending_packets_to_be_written(self):
        # Returns if any data packets to be written are available.
        return len(self.data_buffer) != 0

    def request_file(self, file_path_on_server):
        """
                  2 Bytes  String   1 Byte  String  1 Byte
                  ╔══════╦══════════╦═════╦════════╦═════╗
        RRQ       ║  01  ║ Filename ║  0  ║  Mode  ║  0  ║
                  ╚══════╩══════════╩═════╩════════╩═════╝
        """
        # Generates a READ request with the specified file name using the format illustrated.
        self.is_RRQ = True
        self.file_name = file_path_on_server
        self.expected_block_num = 1
        pull_request = [0, self.TftpPacketType.RRQ.value]
        file_name_bytes = list(struct.pack(f"!{len(file_path_on_server)}s", file_path_on_server.encode("ascii")))
        pull_request.extend(file_name_bytes)
        pull_request.append(0)
        mode_bytes = list(struct.pack(f"!{len(self.MODE)}s", self.MODE.encode("ascii")))
        pull_request.extend(mode_bytes)
        pull_request.append(0)
        return pull_request

    def upload_file(self, file_path_on_server):
        """
                  2 Bytes  String   1 Byte  String  1 Byte
                  ╔══════╦══════════╦═════╦════════╦═════╗
        WRQ       ║  02  ║ Filename ║  0  ║  Mode  ║  0  ║
                  ╚══════╩══════════╩═════╩════════╩═════╝
        """
        # Generates a WRITE request with the specified file name using the format illustrated.
        self.is_RRQ = False
        self.file_name = file_path_on_server
        self.expected_block_num = 0
        push_request = [0, self.TftpPacketType.WRQ.value]
        file_name_bytes = list(struct.pack(f"!{len(file_path_on_server)}s", file_path_on_server.encode("ascii")))
        push_request.extend(file_name_bytes)
        push_request.append(0)
        mode_bytes = list(struct.pack(f"!{len(self.MODE)}s", self.MODE.encode("ascii")))
        push_request.extend(mode_bytes)
        push_request.append(0)
        return push_request

    def _get_error_packet(self, error_code):
        """
                  2 Bytes   2 Bytes    String  1 Byte
                  ╔══════╦═══════════╦════════╦═════╗
        ERROR     ║  05  ║ ErrorCode ║ ErrMsg ║  0  ║
                  ╚══════╩═══════════╩════════╩═════╝
        """
        # Generate an ERROR packet to be sent to the server using the format illustrated.
        self.print_error(error_code)
        error = self.TftpErrorCodes.ERROR_CODES.get(error_code)
        error_packet = struct.pack(f"!HH{len(error)}sx", self.TftpPacketType.ERROR.value,
                                   error_code, error.encode("ascii"))
        return error_packet

    def unknown_id_response(self, error_code):
        # When a server port tries to send data to a client that has not requested anything from it,
        # it replies with an "Unknown transfer ID" ERROR packet.
        error = self.TftpErrorCodes.ERROR_CODES.get(error_code)
        error_packet = struct.pack(f"!HH{len(error)}sx", self.TftpPacketType.ERROR.value,
                                   error_code, error.encode("ascii"))
        return error_packet

    def _write_to_file(self, file_path_on_client):
        # Write all the received data packets to the disk.
        file = open(file_path_on_client, "wb")
        while self._has_pending_packets_to_be_written():
            try:
                file.write(bytearray(self._get_next_data_packet()))
            except MemoryError:
                return False
        file.close()
        return True

    def _read_from_file(self, file_path_on_server):
        # Read the whole file into memory.
        file = open(file_path_on_server, "rb")
        self.data_buffer = list(file.read())
        # Partition the data into packets.
        self.data_buffer = [self.data_buffer[x:x+self.PACKET_SIZE] for x in
                            range(0, len(self.data_buffer), self.PACKET_SIZE)]
        file.close()

    def print_error(self, error_code):
        print("[CLIENT ERROR]", self.TftpErrorCodes.ERROR_CODES.get(error_code))


# GLOBAL VARIABLES
tftp_processor = TftpProcessor()


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


def do_socket_logic(client_socket, server_address, request):
    # Responsible for communicating with the server
    # Making the first request to the server to get the port to listen to.
    client_socket.sendto(bytearray(request), server_address)
    packet, server_address = client_socket.recvfrom(4096)
    response = tftp_processor.process_udp_packet(packet, server_address)
    if not response:
        terminate(client_socket)
    while not tftp_processor.is_done:
        client_socket.sendto(response, server_address)
        if tftp_processor.is_error:
            terminate(client_socket)
        response = receive(client_socket, server_address)
        if not response:
            terminate(client_socket)
    if tftp_processor.is_RRQ:
        client_socket.sendto(response, server_address)
    else:
        client_socket.sendto(response, server_address)
        receive(client_socket, server_address)
    print("SUCCESS!")
    close_socket(client_socket)


def receive(client_socket, server_address):
    # Only listen to the agreed upon server port and ignore any other port.
    while True:
        packet, address = client_socket.recvfrom(4096)
        if address == server_address:
            break
        else:
            client_socket.sendto(tftp_processor.unknown_id_response(5), address)
    response = tftp_processor.process_udp_packet(packet, address)
    return response


def parse_user_input(operation, client_socket, file_name=None):
    # Get the response of the client to be sent to the server.
    if operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        if is_file_exists(file_name):
            tftp_processor.print_error(6)
            terminate(client_socket)
        return tftp_processor.request_file(file_name)
    elif operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        if not validate_file(file_name):
            terminate(client_socket)
        return tftp_processor.upload_file(file_name)
    else:
        tftp_processor.print_error(4)
        terminate(client_socket)


def is_file_exists(file_name):
    try:
        file = open(file_name, "r")
        file.close()
        return True
    except FileNotFoundError:
        return False


def validate_file(file_name):
    # Check the given file for errors.
    try:
        file = open(file_name, "r")
        file.close()
        return True
    except FileNotFoundError:
        tftp_processor.print_error(1)
        return False
    except PermissionError:
        tftp_processor.print_error(2)
        return False


def close_socket(socket_to_close):
    print("Closing socket")
    socket_to_close.close()


def terminate(socket_to_close):
    print("Program execution failed.")
    close_socket(socket_to_close)
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
                f"[FATAL] The command-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():
    # Printing header
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # Default values are provided.
    # The IP address of the server.
    ip_address = get_arg(1, "127.0.0.1")
    # The operation to perform.
    operation = get_arg(2, "push")
    # The file to perform the operation on.
    file_name = get_arg(3, "512.txt")

    client_socket, server_address = setup_sockets(ip_address)
    request = parse_user_input(operation, client_socket, file_name)
    do_socket_logic(client_socket, server_address, request)


if __name__ == "__main__":
    main()
