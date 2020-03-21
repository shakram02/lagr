import sys
import os
import enum
import struct
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
    """
     Value     Meaning
   0         Not defined, see error message (if any).   
   1         File not found.   
   2         Access violation.   
   3         Disk full or allocation exceeded.   
   4         Illegal TFTP operation.   
   5         Unknown transfer ID.   
   6         Unknown transfer ID.   
   7         No such user.

    """

    error_msg = ["Not defined, see error message (if any)", "File not found.", "Access violation.",
                 "Disk full or allocation exceeded.", " Illegal TFTP operation.", "Unknown transfer ID.",
                 "Unknown transfer ID.", "No such user."]

    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        AKN = 4
        ERROR = 5

    def __init__(self):
        self.packet_buffer = []
        pass

    def process_udp_packet(self, packet_data, packet_source):
        if packet_source == 1:
            return self._request_file(packet_data)
            #Return the byte array to be send
        elif packet_source == 0:
            out_packet = self._do_some_logic(packet_data)
            # add the packet to be sent to the buffer
            self.packet_buffer.append(out_packet)

        else:
            return self._parse_udp_packet(packet_data)




    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """

        if packet_bytes[1] == 5 :
            # THERE IS AN ERROR
            print("THERE IS AN ERROR :" + self.error_message(packet_bytes[3]))
            sys.exit()
            # error then print the error and exit the system
        else: #send ack
            return (self._ack(packet_bytes[0:4]))



    def _do_some_logic(self, input_packet):
        """
        takes input block number and data bytes and return data packet
        2 bytes    2 bytes       4096 bytes
        ---------------------------------
       | 03    |   Block #  |    Data    |
        """
        requested_string = bytes([0, 3]) + bytes(input_packet)
        req = bytearray(requested_string)
        return requested_string

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        # Returns if any packets to be sent are available.
        return len(self.packet_buffer) != 0

    def _request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        this will return the packed request to send to the server

        THE FORMAT OF RRQ IS
        2 BYTES :  STRING   : 1 BYTE : STRING : 1 BYTE :
        OPCODE :  FILE NAME :    0   : MODE   :     0  :

        """

        # RRQ
        mode = "octet"
        requested_string = '\0\u0001{}\0{}\0'.format(file_path_on_server, mode)
        req = bytearray(requested_string, 'utf-8')
        return req

    def upload_file(self, file_path_on_server):
        # creat WRQ to be sent to the server
        mode = "octet"
        requested_string = '\0\u0002{}\0{}\0'.format(file_path_on_server, mode)
        req = bytearray(requested_string, 'utf-8')
        return req
        pass

    def _ack(self, block_number):
        """
        This method is for helping out making the acknowledgment
        to be send to the server
        to send more packets

        2 BYTES     :    2 BYTES
        OPCODE (4)  :    BLOCK NUMBER

        """
        req = struct.pack('>BBBB', 0, 4, block_number[2], block_number[3])
        return req

    def error_message(self, errornum):
        """
        It returns the error found
        """
        return self.error_msg[errornum]


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    # creating the UDP socket , passing my IP address and the type of socket --DATAGRAM--
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # server IP and port number 69
    return client_socket


def do_socket_logic(mode, client_socket, address):
    if (mode == 1):  # recvfrom
        file_block, server = client_socket.recvfrom(1024)
        return file_block, server

    else:  # sendto , the mode contains the bytearray
        client_socket.sendto(mode, address)
        return 0


def parse_user_input(address, operation, file_name=None):
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        return 1
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        return 2
    else:
        print("There is an error in the operation..")
        return 0


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
    tftp_processor = TftpProcessor()
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    script, ip_address, operation, file_name = sys.argv
    ip_address = get_arg(1, ip_address)
    operation = get_arg(2, operation)
    file_name = get_arg(3, file_name)

    op_check = parse_user_input(ip_address, operation, file_name)

    # connection setup
    if op_check != 0:
        client_socket = setup_sockets(ip_address)
        server_address = (ip_address, 69)

    if op_check == 1:
        print("uploading ..")

        # sending WRQ
        do_socket_logic(tftp_processor.upload_file(file_name), client_socket, server_address)
        akn_err, send_port = do_socket_logic(1, client_socket, server_address)
        if akn_err[1] == 5:  # error exists in the sent packet

            print("THERE IS AN ERROR :" + tftp_processor.error_message(akn_err[3]))
            return 0

        # get file size
        status = os.stat(file_name)
        packet_num = int(status.st_size / 512) + 1
        f = open(file_name, "rb")
        block_no = 1

        # initialize the buffer
        tftp_processor.__init__()

        # read file packets and push them to the buffer
        while packet_num != 0:
            packet_data = block_no.to_bytes(2, "big") + bytes(f.read(512))
            tftp_processor.process_udp_packet(packet_data, 0)
            packet_num -= 1
            block_no += 1

        # send the data packets
        while tftp_processor.has_pending_packets_to_be_sent():
            packet_to_be_sent = tftp_processor.get_next_output_packet()
            do_socket_logic(packet_to_be_sent, client_socket, send_port)
            akn_err, send_port = do_socket_logic(1, client_socket, send_port)
            if akn_err[1] == 5:  # error exists in the sent packet

                print("THERE IS AN ERROR :" + tftp_processor.error_message(akn_err[3]))
                sys.exit()


        print("file uploaded successfully")

    elif op_check == 2:
        print("downloading..")
        """
        --DOWNLOAD--

        we need to wait to recieve a block from the server
        when we recieve a block then we need to send an ack. to the server
        in doing so we wont send the whole data back to the server telling that we recieved it
        we will only send the block number
        Bare in mind that we'll recieving a file 
        then we'll have to CREATE a file with the same name 
        to stores the blocks send from the server
        the file is binary

        """
        file_downloaded = open(file_name, "wb")

        do_socket_logic(tftp_processor.process_udp_packet(file_name,1), client_socket, server_address)

        while 1:
            file_block, server = do_socket_logic(1, client_socket, 0)
            """
            if the packet has opcode 05 then ERROR
            else it continues normally
            """

            tftp_processor.process_udp_packet(file_block,file_block[1])
            """
             The first 2 bytes are the opcode then the second 2 bytes are the block number
             the byte array was returned from the tftp processor
            """

            do_socket_logic(tftp_processor.process_udp_packet(file_block,4), client_socket, server)
            file_downloaded.write(file_block[4:])
            """
            check the length of the data 
            it finishes when its length is less than 516 
            END OF FILE

            """
            if len(file_block) < 516:
                return 0


if __name__ == "__main__":
    main()
