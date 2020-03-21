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
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERR = 5

    def _init_(self):
        self.packetArray = {"RRQ": "!H{}sx{}sx",
                            "WRQ": "!H{}sx{}sx",
                            "ACK": "!HH",
                            "DATA": "!HH{}s",
                            "ERR": "!HH{}sx"}
        self.file = True
        self.error = False
        self.state = None
        self.mode = 'octet'



        """
        Add and initialize the internal fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.data_buffer = []
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
        if type(out_packet) == str:
            print(out_packet)
            return

        elif out_packet is None:
            print("Upload Complete")
            return



        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        #Opcode is the fixed first 2 bytes in an array, we look through them
        opcode = int.from_bytes(packet_bytes[0:2],byteorder='big')
        if opcode == 4:
            return struct.unpack(self.packetArray["ACK"], packet_bytes)
        elif opcode == 3:
            size = len(packet_bytes) - 4
            return struct.unpack(self.packetArray["DATA"].format(size), packet_bytes)
        elif opcode == 5:
            size = len(packet_bytes) - 5
            return struct.unpack(self.packetArray["ERR"].format(size), packet_bytes)


    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        opcode = input_packet[0]

        if opcode == 4:
            blockNo = input_packet[1]
            if len(input_packet) != 512:
                self.error = True
            return struct.pack(self.formatStrings["ACK"], self.TftpPacketType.ACK.value, blockNo)
        elif opcode == 3:
            # To get exactly how many 512 bytes in a single file
            blockNo = input_packet[1] + 1
            if input_packet[1] == len(self.data_buffer):
                self.error = True
            packetDATA = None
            if len(self.data_buffer) != 0:
                data = self.data_buffer.pop(0)
                data_size = len(data)
                packetDATA = struct.pack(self.formatStrings["DATA"].format(data_size), self.TftpPacketType.DATA.value,
                                         blockNo, data)
            return packetDATA
        elif opcode == 5:
            err_msg = {
                0: "Not defined, see error message (if any).",
                1: "File not found.",
                2: "Access violation.",
                3: "Disk full or allocation exceeded.",
                4: "Illegal TFTP operation.",
                5: "Unknown transfer ID.",
                6: "File already exists.",
                7: "No such user."
            }
            err_code = input_packet[1]
            print(err_msg[err_code])
            return " "

    def _processFile (self, fileData):
        self.file.write(fileData)




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


        pass



    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """

        def chunck_list(lst, chunck_size):
            for i in range(0, len(lst), chunck_size):
                yield lst[i:i + chunck_size]
        try:

            f = open(file_path_on_server, "rb")

        except IOError:
            print("File not accessible")

        self.f = open(file_path_on_server, "rb")
        linelist = f.read()
        lst = list(linelist)

       # print(list(chunck_list(lst, 512)))

        file_length = len(file_path_on_server)
        self.state = "Upload"
        mode_length = len("octet")
        formatString = self.packetArray["WRQ"].format(file_length, mode_length)
        construct_write_request = struct.pack(formatString, self.TftpPacketType.WRQ.value, file_path_on_server.encode('ascii'),
                                    self.mode.encode('ascii'))
        return construct_write_request


        pass


def check_file_name():
    script_name = os.path.basename(_file_)
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
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (address, 69)


    return clientsocket, server_addr


def do_socket_logic(processor, socket, address):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """

    dataBytes, dataSource = socket.recvfrom(1000)
    processor.process_udp_packet(dataBytes, dataSource)
    if processor.has_pending_packets_to_be_sent():
        socket.sendto(processor.get_next_output_packet(), dataSource)
        if processor.error:
            return

    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.

    processor = TftpProcessor()
    clientsocket, server_addr = setup_sockets(address)


    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        construct_write_request = processor.upload_file(file_name)
        clientsocket.sendto(construct_write_request, server_addr)
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")

    do_socket_logic(processor, clientsocket, address)


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
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if _name_ == "_main_":
    main()