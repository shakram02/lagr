# Don't forget to change this file's name before submission.
import struct
import sys
import os
import enum
import socket



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
        self.array = []
        self.exit = 0
        self.filename = None
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
        opcode = int.from_bytes(packet_bytes[:2],byteorder="big")
        if opcode == 3:
            return struct.unpack(f">HH{len(packet_bytes)-4}s", packet_bytes)
        elif opcode == 4:
            return struct.unpack(">HH", packet_bytes)
        elif opcode == 5:
            return struct.unpack(f">HH{len(packet_bytes)-5}sx", packet_bytes)
        pass

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        opcode = input_packet[0]
        if opcode == 3:
            self.array.append(input_packet[-1])
            if len(input_packet[-1]) != 512:
                self.exit = 1
            return struct.pack(">HH", 4, input_packet[1])
        elif opcode == 4:
            if len(self.array) == 0:
                exit(-1)
            data = self.array.pop(0)
            length = len(data)
            block_num = input_packet[1]+1
            return struct.pack(f">HH{length}s", 3, block_num, data)
        elif opcode == 5:
            print(input_packet[2].decode('ascii'))
            exit(-1)

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

        file_len = len(file_path_on_server)
        mode = len("octet")
        self.filename = file_path_on_server
        types = TftpProcessor.TftpPacketType.RRQ.value
        return struct.pack(f">H{file_len}sx{mode}sx", types, file_path_on_server.encode("ascii"), "octet".encode("ascii"))

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        types = TftpProcessor.TftpPacketType.WRQ.value
        file_len = len(file_path_on_server)
        mode = len("octet")
        self.file_div(file_path_on_server)
        return struct.pack(f">H{file_len}sx{mode}sx", types, file_path_on_server.encode("ascii"), "octet".encode("ascii"))

    def file_div(self, file_path):
        try:
            file = open(file_path, "rb")
        except IOError:
            print("No file found with given name")
            exit(-1)
        temp = file.read(512)
        self.array.append(temp)
        while True:
            temp = file.read(512)
            if temp == b'':
                break
            self.array.append(temp)


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
    worker = TftpProcessor()
    request = None

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        request = worker.upload_file(file_name)
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        request = worker.request_file(file_name)

    client_socket.sendto(request, server_address)
    server_packet, server_address = client_socket.recvfrom(1024)
    worker.process_udp_packet(server_packet, server_address)

    while worker.has_pending_packets_to_be_sent():
        client_socket.sendto(worker.get_next_output_packet(), server_address)
        print("[CLIENT] Done!")
        if worker.exit == 1:
            file = open(worker.filename, "wb")
            for bytes in worker.array:
                file.write(bytes)
            break
        server_packet, server_address = client_socket.recvfrom(1024)
        print("[CLIENT] IN", server_packet)
        worker.process_udp_packet(server_packet, server_address)


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
