# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
from struct import pack, unpack
from pathlib import Path


class TftpProcessor(object):
    """
    Implements logic for a TFTP server.
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
        # holds the next buffer to be transmitted
        self.packet_buffer = []
        # holds all the numbers of blocks that have either been generated for tramission or accepted
        self.block_nums = []
        # name of the file to be sent or recieved
        self.file_name = ""
        # boolean to indicate that last data packet< 512 MB
        self.last_data = 0
        # holds the data chunks that has been pre loaded and are ready for transmission
        self.data_blocks = []
        # boolean to indicate an error has occured and error packet has been sent
        self.err = 0
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
        self.client = packet_data
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
        try:
            # extract the opcode from the recieved packet ( first 2 bytes )
            opcode = unpack('!h', packet_bytes[0:2])
        except:  # in case opcode extraction has failed, send an error packet to indicate the packet is broken ; send error packet
            return 0, None, None

        opcode = opcode[0]  # needed because unpack return a tuple
        if opcode == self.TftpPacketType.RRQ.value:  # server recieved a RRQ
            print('Recieved a RRQ')
            filename_len = packet_bytes.find(b'\x00', 2)
            try:  # extarct the filename and mode from the packet
                filename = unpack('!'+str(filename_len-2)+'s',
                                  packet_bytes[2:filename_len])[0].decode()
                mode_index = packet_bytes.find(b'\x00', filename_len + 1)
                mode = unpack('!'+str(mode_index-filename_len-1)+'s',
                              packet_bytes[filename_len+1: mode_index])[0].decode()
            except:  # if unpacking has failed then data packet is broken ; send error packet
                return -1*self.TftpPacketType.RRQ.value, None, None
            return opcode, filename, mode

        if opcode == self.TftpPacketType.WRQ.value:  # server recived a WRQ packet
            print('recieved a WRQ')
            filename_len = packet_bytes.find(b'\x00', 2)
            try:  # extarct filename and mode from WRQ
                filename = unpack('!'+str(filename_len-2)+'s',
                                  packet_bytes[2:filename_len])[0].decode()
                mode_index = packet_bytes.find(b'\x00', filename_len + 1)
                mode = unpack('!'+str(mode_index-filename_len-1)+'s',
                              packet_bytes[filename_len+1: mode_index])[0].decode()
            except:  # if unpacking has failed then data packet is broken ; send error packet
                return -1*self.TftpPacketType.WRQ.value, None, None
            return opcode, filename, mode

        if opcode == self.TftpPacketType.DATA.value:  # server recieved a DATA packet from client
            end = len(packet_bytes)
            try:  # extract block Num and data block
                blockNum = unpack('!h', packet_bytes[2:4])
                dataBlock = unpack('!'+str(end-4)+'s',
                                   packet_bytes[4:end])[0]
            except:  # if unpacking has failed then data packet is broken ; send error packet
                return -1*self.TftpPacketType.DATA.value, None, None
            print(f"Recieved DATA packet {blockNum[0]}")
            return opcode, blockNum, dataBlock

        if opcode == self.TftpPacketType.ACK.value:  # sevrer recieved an ACK from client
            try:  # extract blcokNum from ACK packet
                opcode, blockNum = unpack('!hh', packet_bytes)
            except:  # if unpacking has failed then data packet is broken ; send error packet
                return -1*self.TftpPacketType.ACK.value, None, None
                # if unpacking succeeds append the block num in ACK to tftp list
            self.block_nums.append(blockNum)
            return opcode, blockNum, None

        if opcode == self.TftpPacketType.ERROR.value:  # server recieved error packet from client
            format_str = "!hh{}sb".format(len(packet_bytes) - 5)
            try:  # extarct erro code and error msg
                opcode, err_code, err_msg, _ = unpack(format_str, packet_bytes)
            except:  # if unpacking fails ERROR packet is broken ; error packet backfires lol
                # a side note that this actually isn't necessary since the server would terminate its connection upon sending
                # its error packet ; however I kept this here for similarity measures and code coherence
                return -1*self.TftpPacketType.ERROR.value, None, None
            return opcode, err_code, err_msg

        # if opcode is not in {1,2,3,4,5}, return -1 indicating that the opcode recieved by the client makes no sense
        return -7, None, None

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        opcode, arg2, arg3 = input_packet  # spread out the parameters recieved from the parsing function

        # if opcode is -1 ( manually generated by packet parser) then the packet recieved isn't valid ; send error packet
        if opcode == 0:
            err_msg = 'Opcode could not be unpacked'
            format_str = "!hh{}sb".format(len(err_msg))
            err_packet = pack(
                format_str, 5, 0, bytes(err_msg, 'ascii'), 0)
            self.err = 1
            return err_packet
        if opcode < 0:
            # notice here that any corrupt packet returns a value that equals the negative sign of its opcode
            err_msg = f'{self.TftpPacketType(abs(opcode)).name} packet format invalid'
            format_str = "!hh{}sb".format(len(err_msg))
            err_packet = pack(
                format_str, 5, 0, bytes(err_msg, 'ascii'), 0)
            self.err = 1
            return err_packet

        # if opcode is 1, then server recieved a RRQ , server responds with first data packet
        if opcode == self.TftpPacketType.RRQ.value:
            filename = arg2
            self.file_name = filename  # store file name for later usage
            print("Sending data for RRQ")
            try:  # open file to read and store its data chunks
                f = open(filename, "rb")
            except FileNotFoundError:  # on failure , send an error packet
                err_msg = 'File does not exist'
                format_str = "!hh{}sb".format(len(err_msg))
                err_packet = pack(
                    format_str, 5, 1, bytes(err_msg, 'ascii'), 0)
                self.err = 1
                return err_packet
            blockNum = 1  # first data block index = 1
            while True:  # read all file and store the data chunks in tftp list
                chunk = f.read(512)  # read exactly 512 mb
                if not chunk:
                    break  # EOF
                self.data_blocks.append(chunk)
            if len(self.data_blocks) < 1:  # file is empty ; send error packet
                err_msg = 'File is empty'
                format_str = "!hh{}sb".format(len(err_msg))
                err_packet = pack(
                    format_str, 5, 0, bytes(err_msg, 'ascii'), 0)
                self.err = 1
                return err_packet
                # get first data block and put in a data packet
            first_chunk = self.get_next_data_block()
            format_str = "!hh{}s".format(len(first_chunk))
            data_packet = pack(format_str, 3, blockNum, first_chunk)
            self.block_nums.append(blockNum)
            return data_packet

        if opcode == self.TftpPacketType.WRQ.value:  # if sever recieved WRQ from client , it must respond with ACK
            filename = arg2
            self.file_name = filename  # store file name for later usage
            data_folder = Path("server_output/")
            filepath = data_folder / self.file_name
            # if file already exists on server, send error packet
            if os.path.isfile(filepath):
                err_msg = 'File already exists'
                format_str = "!hh{}sb".format(len(err_msg))
                err_packet = pack(
                    format_str, 5, 6, bytes(err_msg, 'ascii'), 0)
                self.err = 1
                return err_packet
            print("sending ACK for WRQ")
            format_str = "!hh"
            # send ACK packet number 0
            ack_packet = pack(format_str, 4, 0)
            return ack_packet

        if opcode == self.TftpPacketType.DATA.value:  # if server recieved data packet, it must respond with ACK
            blockNum = arg2[0]
            dataBlock = arg3
            first_write = 0
            # if no blockNum has been appended yet then this DATA packet must be the first
            if len(self.block_nums) == 0:
                if blockNum != 1:  # if blockNum recieved from server isn't 1 ; send error packet
                    err_msg = 'Data Packet:Block Number invalid'
                    format_str = "!hh{}sb".format(len(err_msg))
                    err_packet = pack(
                        format_str, 5, 0, bytes(err_msg, 'ascii'), 0)
                    self.err = 1
                    return err_packet
                first_write = 1
            # otherwise the blockNum must be bigger than orevious blockNum with exactly 1
            elif blockNum != self.block_nums[-1] + 1:
                err_msg = 'Data Packet:Block Number invalid'    # if not so; send error packet
                format_str = "!hh{}sb".format(len(err_msg))
                err_packet = pack(
                    format_str, 5, 0, bytes(err_msg, 'ascii'), 0)
                self.err = 1
                return err_packet

            # if passed all cases ; add the new blockNum to the tftp list
            self.block_nums.append(blockNum)
            data_folder = Path("server_output/")
            # print(self.file_name)
            filepath = data_folder / self.file_name
            if first_write:
                # open file in writing mode(first time only)
                f = open(filepath, "wb")
                first_write = 0  # reset flag
            else:
                f = open(filepath, "ab")  # open file in appending mode
            # write the newly recieved data packet into the file
            f.write(dataBlock)
            # if size of data packet < 512 , it is the last one ; toggle boolean
            if sys.getsizeof(dataBlock) < 512:
                self.last_data = 1
            # generate the ack packet with same blockNum as recently receved data apacket
            format_str = "!hh"
            ack_packet = pack(format_str, 4, self.block_nums[-1])
            return ack_packet

        if opcode == self.TftpPacketType.ACK.value:  # if server recieved an ACK packet, respond with data packet
            blockNum = arg2
            # if ACK number isn't same as previously sent DATA packet ; send error packet
            if blockNum != self.block_nums[-1]:
                err_msg = 'ACK Packet:Block Number invalid'
                format_str = "!hh{}sb".format(len(err_msg))
                err_packet = pack(
                    format_str, 5, 0, bytes(err_msg, 'ascii'), 0)
                self.err = 1
                return err_packet

            # if all data chunk has been sent then return nothing since what we just recieved is the last ACK packet
            if not self.has_pending_blocks_to_be_sent():
                # this could actually be made in a cleaner way but I didn't want to change the pipeline of completely
                # processing the packet before deciding what to do
                return None
            print("Sending data for ACK")
            blockNum = self.block_nums[-1] + 1  # blockNUm of next data block
            # print(chunk)
            chunk = self.get_next_data_block()  # get data block
            # if size of data packet < 512 , it is the last one ; toggle boolean
            if sys.getsizeof(chunk) < 512:
                self.last_data = 1
            format_str = "!hh{}s".format(len(chunk))  # creat data packet
            data_packet = pack(format_str, 3, blockNum, chunk)
            self.block_nums.append(blockNum)
            return data_packet

        if opcode == self.TftpPacketType.ERROR.value:  # if client recieved error packet ; terminate
            print("Server recieved an error", arg3)
            return None

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

    def get_next_data_block(self):  # returns the next data block
        return self.data_blocks.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    # returns if any data blocks are yet to be transmitted
    def has_pending_blocks_to_be_sent(self):
        return len(self.data_blocks) != 0


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):  # create a server socket and return it
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    # Don't forget, the server's port is 69 (might require using sudo on Linux)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    Port = 69
    server_address = (address, Port)
    server_socket.bind(server_address)  # bind socket to port 69
    print(f"TFTP server started on on [{address}]...")
    return server_socket


def do_socket_logic(server_socket):  # recieve a packet
    server_socket.settimeout(10)  # timeout after 5 seconds
    try:
        data, client = server_socket.recvfrom(4096)
        return data, client
    except:
        return None, None


def send_to_client(server_socket, out_packet, client):  # send a packet
    server_socket.sendto(out_packet, client)
    print(f'Packet sent to client')


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplied, it tries to use a default value.
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
    # The IP of the server.
    ip_address = get_arg(1, "127.0.0.1")
    server_socket = setup_sockets(ip_address)

    """Start of code"""

    tftp_server = TftpProcessor()  # create a tftp object
    while True:  # while tru keep listening
        # re initialize the block_num list to remove previous client info
        while len(tftp_server.block_nums) > 0:
            tftp_server.block_nums.pop(0)
        # listen and recieve a packet from client
        print(">>>>>>>Waiting to connect with another client(Timeout in 10 seconds)")
        data, client = do_socket_logic(server_socket)
        if data == None:  # timeout
            print("Server timed out. Will terminate conection")
            server_socket.close()
            return
        tftp_server.process_udp_packet(data, client)  # process the RRQ or WRQ
        while True:  # while try keep interacting with client to send and recieve packets
            out_packet = tftp_server.get_next_output_packet()  # get next packet to send
            if out_packet == None:  # termination due to recieveing error packet
                break
            send_to_client(server_socket, out_packet, client)  # send packet
            if tftp_server.err:  # termination due to sending error packet
                tftp_server.err = 0
                print(
                    "Server will close connection with current client due to an error packet!")
                break
            if tftp_server.last_data:  # normal termination
                tftp_server.last_data = 0
                break
            # recieve packet from client
            data, _ = do_socket_logic(server_socket)
            # On fisrt timeout, re transmit. On second timeout, close connection
            if data == None:
                print("Server timed out. Will retransmit last packet")
                send_to_client(server_socket, out_packet,
                               client)  # send packet
                data, _ = do_socket_logic(server_socket)
            if data == None:
                print("Server timed out again. Will terminate conection")
                break
            tftp_server.process_udp_packet(
                data, client)  # process recieved packet


if __name__ == "__main__":
    main()
