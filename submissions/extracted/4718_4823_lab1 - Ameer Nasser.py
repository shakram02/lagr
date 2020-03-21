# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
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
        # PACKET_NAME = OPCODES
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERR = 5

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

        opcode, block_number, data = self._parse_udp_packet(packet_data)
        # print(block_number)
        ack_packet = self.create_ack_packet(block_number)

        # out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        # self.packet_buffer.append(out_packet)
        return ack_packet

    def create_ack_packet(self, block_number):
        opcode = list(bytearray([0, 4]))
        opcode.extend(block_number)
        #print(bytearray(opcode))
        return bytearray(opcode)


    def string_to_bytearray(self, file_name):
        b = bytearray()
        b.extend(map(ord, file_name))
        return list(b)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        packet_list = list(packet_bytes)
        opcode = packet_list[1]
        block_number = packet_list[2:4]
        #block_number = struct.unpack('>bb', packet_bytes[2:4])
        data = packet_list[4:]

        return opcode, block_number, data


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
        read_request = bytearray([0, 1])
        file_name = file_path_on_server
        # print(file_name)
        bytes_file_name = self.string_to_bytearray(file_name)
        # print(bytes_file_name)
        read_request.extend(bytes_file_name)
        read_request.extend([0])
        bytes_mode = self.string_to_bytearray("octet")
        read_request.extend(bytes_mode)
        read_request.extend([0])
        #print(read_request)
        return read_request

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        write_request = list(bytearray([0, 2]))
        file_name = file_path_on_server
        # print(file_name)
        bytes_file_name = self.string_to_bytearray(file_name)
        # print(bytes_file_name)
        write_request.extend(bytes_file_name)
        write_request.extend([0])
        bytes_mode = self.string_to_bytearray("octet")
        write_request.extend(bytes_mode)
        write_request.extend([0])
        # print(bytearray(read_request))
        return bytearray(write_request)





###############################END OF TftpProcessor###############################

def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def talk_to_server(my_socket, bytearrayy, port):
    server_address = ("127.0.0.1", port)
    my_socket.sendto(bytearrayy, server_address)
    recieved_data, source = my_socket.recvfrom(4096)
    #print(recieved_data)
    return recieved_data, source


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # client_socket.bind((address, 69))
    return client_socket


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        try:
            print(f"Attempting to upload [{file_name}]...")
            infile = open(file_name, 'rb')
            client_socket = setup_sockets(address)
            tftp_processor = TftpProcessor()
            WRQbytearray = tftp_processor.upload_file(file_name)
            #print(WRQbytearray)
            recieved_data, source = talk_to_server(client_socket,WRQbytearray,69)
            #print(recieved_data)

            chunks = []

            while True:
                chunk = infile.read(512)
                chunks.append(chunk)
                if not chunk: break



            for i in range(1, len(chunks)):
                data_packet = bytearray([0, 3])
                block_number = struct.pack('>H', i)
                data_packet.extend(block_number)
                data_packet.extend(bytearray(chunks[i-1]))
                talk_to_server(client_socket,data_packet,source[1])
                #print(chunks[i-1])
                #print("\n\n")
            print(file_name + "  uploaded successfully")
        except:
            print("you have no file named  "+ file_name)


    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        client_socket = setup_sockets(address)
        tftp_processor = TftpProcessor()
        RRQbytearray = tftp_processor.request_file(file_name)
        recieved_data, source = talk_to_server(client_socket, RRQbytearray, 69)
        opcode = recieved_data[1]
        if (opcode != 5):
            f = open(file_name, "w+")
            f.write(recieved_data[4:].decode("utf-8"))

            while  (len(recieved_data[4:]) == 512):
                ack_packet = tftp_processor.process_udp_packet(recieved_data, source)
                recieved_data, source = talk_to_server(client_socket, bytearray(ack_packet), source[1])
                data = recieved_data[4:]
                f.write(data.decode("utf-8"))

                if len(data) < 512:
                    break
            print(file_name + "  Downloaded successfully")
            f.close()
        else:
            print(recieved_data[4:].decode("utf-8"))


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
    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    if len(sys.argv) > 2:
        ip_address = get_arg(1, "127.0.0.1")
        operation = get_arg(2, "pull")
        file_name = get_arg(3, "test.txt")
    else:
        print("*" * 50)
        print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
        check_file_name()
        print("*" * 50)
        user_input = input("type your command as follows \t ip_address operation filename\n")
        user_inputs = user_input.split()
        ip_address = user_inputs[0]
        operation = user_inputs[1]
        file_name = user_inputs[2]

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
