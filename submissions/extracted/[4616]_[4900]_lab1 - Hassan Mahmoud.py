
import sys
import os
import enum
import struct
import socket

chunks = []
server_add = []


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
        self.chunks = []
        self.count = 0
        self.packet_buffer = []
        self.file = bytearray()
        self.flag = False
        self.file_name_to_be_created = ""
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
        if packet_source != server_add[0]:
            error = bytearray()
            error.append(0)
            error.append(5)
            error.append(0)
            error.append(5)
            error += "SERVER SENT FROM DIFFERENT PORT".encode("utf-8")
            error.append(0)
            self.packet_buffer.append(error)
        else:
            in_packet = self._parse_udp_packet(packet_data)
            out_packet = self._do_some_logic(in_packet)

            # This shouldn't change.
            self.packet_buffer.append(out_packet)

        print('here')

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        opcode = packet_bytes[:2]
        #print("opcode is ",opcode)
        rest = packet_bytes[2:]
        if opcode == b'\x00\x01':                     # RRQ
            type = 1
            for i in range(len(rest)):          # GET LENGTH OF FILE NAME
                if i == 48:
                    break
            file_name = rest[:i]
            file_name = file_name.decode("utf-8")
            return type, file_name

        elif opcode == b'\x00\x02':                   # WRQ
            type = 2
            for i in range(len(rest)):          # GET FILE NAME
                if i == 48:
                    break
            file_name = rest[:i]
            file_name = file_name.decode("utf-8")
            return type, file_name

        elif opcode == b'\x00\x03':                   # DATA
            # print("DATA RECEIVED !!!!!!!!!!!!")
            type = 3
            block_number = rest[:2]             # DATA BLOCK NUMBER
            # print(block_number)
            block_number = struct.unpack("!h",block_number)
            # print(block_number)
            block_number = block_number[0]
            data = rest[2:]                     # DATA ITSELF
            return type, block_number, data

        elif opcode == b'\x00\x04':                   # ACK
            type = 4
            block_number = rest[:2]
            block_number = struct.unpack("!h", block_number)
            block_number = block_number[0]
            return type, block_number

        elif opcode == b'\x00\x05':                   # ERROR
            type = 5
            error_code = rest[:2]
            error_code = struct.unpack("!h", error_code)
            error_code = error_code[0]
            error_message = rest[2:-1]
            error_message = error_message.decode("utf-8")
            return type, error_code, error_message
        else:
            type = 6
            return type,"invalid code"

        pass

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        opcode = input_packet[0]
        if opcode == 1:
            print("RRQ")

        elif opcode == 2:
            print("WRQ")

        elif opcode == 3:
            print ("do some logic")

            block_number = input_packet[1]
            data = input_packet[2]
            x = 4 + len(input_packet[2])
            if x>516:
                error = bytearray()
                error.append(0)
                error.append(5)
                error.append(0)
                error.append(0)
                error += "DATA MORE THAN 516 BYTES".encode('utf-8')
                error.append(0)
                return error
            #print(data.decode("utf-8"))
            #self.file+=data.decode("utf-8")
            # CONSTRUCT ACK PACKET
            else:
                self.file += data
                out_packet = bytearray()
                out_packet.append(0)
                out_packet.append(4)
                out_packet += struct.pack("!h", block_number)
                print(out_packet)
                fileptr = open(self.file_name_to_be_created, "wb")
                fileptr.write(self.file)
                return out_packet

        elif opcode == 4:
            block_number = input_packet[1]+1
            buf = 512
            # file_name = sys.argv[1]
            file_name = 'test.txt'
            upload_packet = bytearray()
            upload_packet.append(0)
            upload_packet.append(3)
            upload_packet += struct.pack("!h", block_number)
            print(f'Block No: {block_number}')
            upload_packet += chunks[block_number - 1]
            return upload_packet

        elif opcode == 5:
            print("ERROR CODE = ", input_packet[1])
            print("ERROR MESSAGE IS : ", input_packet[2])
            exit()

        else:
            error = bytearray()
            error.append(0)
            error.append(5)
            error.append(0)
            error.append(4)
            error += "ILLEGAL TFTP OPERATION".encode("utf-8")
            error.append(0)
            return error

            # f = open(file_name, "rb")
            # data = f.read(buf)
            # while (data):
            # data = f.read(buf)
                # upload_packet += data.encode("utf-8")

            # f.close()

            print("ACK")


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
        message = bytearray()
        message.append(0)
        message.append(1)
        message += file_path_on_server.encode("utf-8")
        self.file_name_to_be_created += file_path_on_server
        message.append(0)
        message += "octet".encode("utf-8")
        message.append(0)
        # print(message)
        return message

        pass

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        message = bytearray()
        message.append(0)
        message.append(2)
        message += file_path_on_server.encode("utf-8")
        message.append(0)
        message += "octet".encode("utf-8")
        message.append(0)
        # print(message)
        return message

        pass


def check_file_name():
    script_name = os.path.basename(__file__)
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

    pass


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """

    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", 69)
    tftp = TftpProcessor()

    if operation == "push":
        # file_name = sys.argv[1]
        # file_name = 'test.txt'
        buf = 512
        f = open(file_name, "rb")
        data = f.read(buf)
        while data:
            chunks.append(data)
            data = f.read(buf)

        f.close()
        iterations = len(chunks)
        print(iterations)
        print(f"Attempting to upload [{file_name}]...")
        message = tftp.upload_file(file_name)
        client_socket.sendto(message, server_address)
        data, server_address = client_socket.recvfrom(4096)
        server_add.append(server_address)
        j = 0
        for i in range(0, iterations):
            tftp.process_udp_packet(data, server_address)
            client_socket.sendto(tftp.get_next_output_packet(), server_address)
            data, server_address_received = client_socket.recvfrom(4096)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        message = tftp.request_file(file_name)
        client_socket.sendto(message, server_address)
        server_packet = client_socket.recvfrom(4096)
        server_add.append(server_packet[1])
        print("[CLIENT] IN", server_packet)
        tftp.process_udp_packet(server_packet[0], server_packet[1])
        length = len(server_packet[0])
        while length >= 516:
            packet = tftp.get_next_output_packet()
            print("packet = ", packet)
            client_socket.sendto(packet, server_packet[1])

            server_packet = client_socket.recvfrom(4096)
            # print("[CLIENT] IN", server_packet)
            tftp.process_udp_packet(server_packet[0], server_packet[1])
            length = len(server_packet[0])
        packet = tftp.get_next_output_packet()
        client_socket.sendto(packet,server_packet[1])
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
    # parse_user_input("1111", "push", "test.txt")

    """client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    "server_address = ("127.0.0.1", 69)
    messg = x.request_file("test.txt")
    client_socket.sendto(messg, server_address)
    print("[CLIENT] Done!")
    server_packet = client_socket.recvfrom(2048)
    print("[CLIENT] IN", server_packet)"""

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
    file_name = get_arg(3, "test44.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
