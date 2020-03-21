import functools
import operator
import socket
import sys
import os
import enum
import struct
import pathlib

error_flag = 0  # if error packet is sent
termination_flag = 0
ACK_flag = 0  # ack after an error is sent to terminate
corruption_flag = 0  # flag that indicates corrupted data block


def write_files(filename, data):  # fn to write received data in files
    try:
        file = open(filename, "ab+")
        file.write(data.encode())
        file.close()
    except Exception as e:
        global error_flag
        error_flag = 1


def check_file_exists(filename):
    file = pathlib.Path(filename)
    if file.exists():
        return 1
    else:
        return 0


def setup_Socket(address):
    # create datagram socket
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind((address, 69))
    do_socket_logic(serverSocket)


def do_socket_logic(s):
    global termination_flag
    while 1:
        if ACK_flag == 1 and error_flag == 1 or termination_flag == 1:
            print('Socket terminated')
            s.close()
            break
        else:
            print('Waiting to recieve a message')
            data, client_address = s.recvfrom(4096)
            print('received {} bytes from {}'.format(
                len(data), client_address))
            print('data=' + data.decode())
            # check if there is pending packets then send
            if data:

                p.process_udp_packet(data, client_address)

                if p.has_pending_packets_to_be_sent() == 1:  # if there are packet data available in buffer
                    s.sendto(p.get_next_output_packet(), client_address)
                else:
                    print('Socket Terminated')
                    s.close()
                    break

            else:
                termination_flag = 1
                s.close()

    pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


class TftpProcessor(object):
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    class ErrorPacket(enum.Enum):
        NotDefined = 0
        File_not_found = 1
        IllegalOperation = 4
        File_exists = 6

    def __init__(self):
        self.packet_buffer = []
        self.filename = ''
        self.opcode = 0
        self.ACK_block_number = 0
        self.DATA_block_number = 0
        self.data = ""
        self.error_number = 0
        self.error_message = ""
        self.mode = 'octet'
        self.chunksBuffer = []
        pass

    def process_udp_packet(self, packet_data, packet_source):
        global error_flag
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        global termination_flag
        out_packet = b'0'
        byte = 0
        # in_packet = 2
        if in_packet == self.TftpPacketType.RRQ.value:
            # if it's a read req, send first block

            if check_file_exists(self.filename) == 1:
                self.SplitFileIntoChuncks()
                # print(termination_flag)
                if error_flag == 0:
                    self.data = self.chunksBuffer.pop(0)
                    out_packet = struct.pack('!hh{}s'.format(len(self.data)), self.TftpPacketType.DATA.value,
                                             self.DATA_block_number,
                                             self.data)
                else:
                    byte = 0
                    self.error_message = " Persmission denied "
                    out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)),
                                             self.TftpPacketType.ERROR.value,
                                             self.ErrorPacket.NotDefined.value,
                                             self.error_message.encode(),
                                             byte)
            else:

                error_flag = 1
                self.error_message = "    File not found      "
                out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)), self.TftpPacketType.ERROR.value,
                                         self.ErrorPacket.File_not_found.value,
                                         self.error_message.encode(),
                                         byte)

        elif in_packet == self.TftpPacketType.WRQ.value:
            # write in filename
            if check_file_exists(self.filename) == 0:
                if error_flag == 0:
                    out_packet = struct.pack('!hh', self.TftpPacketType.ACK.value, self.DATA_block_number)

                else:
                    self.error_message = " Not Defined "
                    out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)),
                                             self.TftpPacketType.ERROR.value,
                                             self.ErrorPacket.File_exists.value,
                                             self.error_message.encode(),
                                             byte)
            else:
                error_flag = 1
                self.error_message = "File already exists"
                out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)), self.TftpPacketType.ERROR.value,
                                         self.ErrorPacket.File_exists.value,
                                         self.error_message.encode(),
                                         byte)

        elif in_packet == self.TftpPacketType.DATA.value:  # if it's data received,send an ack
            if len(self.data) > 512:
                self.error_message = " Data recieved more than 512 "
                out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)), self.TftpPacketType.ERROR.value,
                                         self.ErrorPacket.IllegalOperation.value,
                                         self.error_message.encode(),
                                         byte)
            elif corruption_flag == 0 and len(self.data) <= 512:
                out_packet = struct.pack('!hh', self.TftpPacketType.ACK.value, self.ACK_block_number)

            else:
                # if data is corrupted
                self.error_message = " Wrong data,Re-Transmit "
                out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)), self.TftpPacketType.ERROR.value,
                                         self.ErrorPacket.NotDefined.value,
                                         self.error_message.encode(),
                                         byte)

        elif in_packet == self.TftpPacketType.ACK.value:
            # if it's an acknologement,send the next block of data
            # print(len(chunksBuffer))
            if self.chuncks_buffer_empty() == 0:
                self.data = self.chunksBuffer.pop(0)
                out_packet = struct.pack('!hh{}s'.format(len(self.data)), self.TftpPacketType.DATA.value,
                                         self.DATA_block_number, self.data)

            else:
                termination_flag = 1

        elif in_packet == self.TftpPacketType.ERROR.value:
            # terminate
            termination_flag = 1

        else:
            self.error_message = "   ILLEGAL TFTP OPERATION      "
            out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)), self.TftpPacketType.ERROR.value,
                                     self.ErrorPacket.IllegalOperation.value,
                                     self.error_message.encode(),
                                     byte)
        # Add the packet to the buffer
        self.packet_buffer.append(out_packet)

    def SplitFileIntoChuncks(self):
        try:
            file = open(self.filename, 'rb')
            while (1):
                chunck = file.read(512)  # reading 512 bytes in each loop
                self.chunksBuffer.append(chunck)
                if len(chunck) < 512:
                    file.close()
                    break
        except Exception as e:
            global error_flag
            error_flag = 1


    def _parse_udp_packet(self, packet_bytes):
        global corruption_flag
        corruption_flag = 0
        global ACK_flag
        global error_flag

        # extract opcode which is the first two bytes
        self.opcode = struct.unpack('>H', packet_bytes[0:2])
        self.opcode = functools.reduce(lambda sub, ele: sub * 10 + ele, self.opcode)
        if self.opcode == self.TftpPacketType.RRQ.value or self.opcode == self.TftpPacketType.WRQ.value:
            if error_flag == 1:
                ACK_flag = 1
            byte_0_index = 0
            count = 0
            for i in range(2, len(packet_bytes)):
                # extract filename in which n bytes filename preceeds 1 byte it's value is 0
                if packet_bytes[i] == 0:
                    # get the index of 0
                    byte_0_index = i
                    break
            # then n bytes file name is byte 0 index - 2 bytes of the opcode
            filename_length = byte_0_index - 2
            for i in range(byte_0_index + 1, len(packet_bytes)):
                # counts the lenth of mode bytes
                count = count + 1
                if packet_bytes[i] == 0:
                    byte_0_index = i
                    break
            count = count - 1
            # unpacking filename
            self.filename = struct.unpack('{}s'.format(filename_length), packet_bytes[2:filename_length + 2])
            # filename tuple to string
            self.filename = functools.reduce(operator.add, self.filename)
            self.filename = self.filename.decode("utf-8")
            # unpacking mode
            self.mode = struct.unpack('{}s'.format(count),
                                      packet_bytes[filename_length + 3:count + filename_length + 3])
            # mode tuple to string
            self.mode = functools.reduce(operator.add, self.mode)
            self.mode = self.mode.decode("utf-8")

            if self.TftpPacketType.RRQ.value == self.opcode:
                print('Reading')
                self.DATA_block_number = 1
            else:
                print('Writing')
                self.DATA_block_number = 0

        elif self.opcode == self.TftpPacketType.ACK.value:
            print('Acknowledging')
            if error_flag == 1:
                ACK_flag = 1
            self.ACK_block_number = struct.unpack('>H', packet_bytes[2:4])
            self.ACK_block_number = functools.reduce(lambda sub, ele: sub * 10 + ele, self.ACK_block_number)
            # adding 1 to send the next data block number
            self.DATA_block_number += 1

        elif self.opcode == self.TftpPacketType.DATA.value:
            if error_flag == 1:
                ACK_flag = 1
            print('Data Packet')
            self.DATA_block_number = struct.unpack('>H', packet_bytes[2:4])
            # data block number tuple to integer
            self.DATA_block_number = functools.reduce(lambda sub, ele: sub * 10 + ele, self.DATA_block_number)
            # if data is sent wrong
            if (self.DATA_block_number - self.ACK_block_number) != 1:
                corruption_flag = 1
            else:
                corruption_flag = 0

                self.ACK_block_number = self.DATA_block_number
                self.data = struct.unpack('{}s'.format(len(packet_bytes) - 4), packet_bytes[4:len(packet_bytes)])
                self.data = functools.reduce(operator.add, self.data)
                self.data = self.data.decode("utf-8")
                write_files(self.filename, self.data)
                # if data ends
                if len(self.data) < 512:
                    global termination_flag
                    termination_flag = 1

        elif self.opcode == self.TftpPacketType.ERROR.value:
            if error_flag == 1:
                ACK_flag = 1
            print('Error Packet')
            self.error_number = struct.unpack('>H', packet_bytes[2:4])
            self.error_number = functools.reduce(lambda sub, ele: sub * 10 + ele, self.error_number)
            byte_0_index = 0
            if len(packet_bytes) > 4:
                for i in range(4, len(packet_bytes)):
                    if packet_bytes[i] == 0:
                        byte_0_index = i
                        break
                error_message_length = byte_0_index - 4
                self.error_message = struct.unpack('{}s'.format(error_message_length),
                                                   packet_bytes[4:error_message_length + 4])
                self.error_message = functools.reduce(operator.add, self.error_message)
                self.error_message = self.error_message.decode("utf-8")

        return self.opcode

    def get_next_output_packet(self):

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):  # checks if buffer is empty or not

        return len(self.packet_buffer) != 0

    def chuncks_buffer_empty(self):  # checks if buffer is empty or not
        if len(self.chunksBuffer) == 0:
            return 1
        else:
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


# global object
p = TftpProcessor()


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
    setup_Socket(ip_address)


if __name__ == "__main__":
    main()
