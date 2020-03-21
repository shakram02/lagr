import functools
import operator
import socket
import sys
import os
import enum
import time
import struct
import pathlib
import itertools

error_flag = 0
termination_flag = 0
ACK_flag = 0
chunksBuffer = []
corruption_flag = 0 #flag that indicates corrupted data block


def wtite_files(filename,data):#fn to write received data in files
    file=open(filename,"a+")
    file.write(data)
    file.close()

def check_file_exists(filename):
    file = pathlib.Path(filename)
    if file.exists():
        return 1
    else:
        return 0


def setup_Socket(address):  # create datagram socket

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind((address, 69))
    do_socket_logic(serverSocket)




def do_socket_logic(s):
    while 1:
     if ACK_flag == 1 and error_flag == 1:
         print('socket terminated')
         s.close()
         break
     else:
        print('Waiting to recieve a message')
        data, client_address = s.recvfrom(4096)
        print('received {} bytes from {}'.format(
            len(data), client_address))
        print('data=' + data.decode())
        # check if there is pending packets then send
        # sent = s.sendto(data, client_address)
        # print('sent {} bytes back to {}'.format(sent, client_address))
        if data:

            p.process_udp_packet(data, client_address)

            if ((p.has_pending_packets_to_be_sent()) == 1):  # if there are packet data available in buffer
                #print('hiiii')
                s.sendto(p.get_next_output_packet(), client_address)
            else:
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
    # packet_data, packet_source = object

    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        self.packet_buffer = []
        self.filename = "test.txt"
        self.opcode = 0
        self.ACK_block_number = 0
        self.DATA_block_number = 0
        self.data = ""
        self.error_number = 0
        self.error_message = ""
        self.mode = 'octet'
        self.command = ""
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = b'0'
        byte = 0
        # in_packet = 2
        if (in_packet == 1):  # if it's a read req, send first block
            if check_file_exists(self.filename) == 1:
                self.SplitFileIntoChuncks()
                # print('buff' + str(self.chunksBuffer[0]))
                print(self.DATA_block_number)
                print('size 2 ='+ str(len(chunksBuffer)))
                self.data = chunksBuffer.pop(0)
                out_packet = struct.pack('!hh{}s'.format(len(self.data)), 3, self.DATA_block_number,
                                         self.data)
                self.packet_buffer.append(out_packet)
                print('size ='+ str(len(chunksBuffer)))
            else:
                global error_flag
                error_flag = 1
                self.error_message = "    File not found      "
                out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)), 5, 1, self.error_message.encode(),
                                         byte)
                self.packet_buffer.append(out_packet)

        elif (in_packet == 2):  # if it's a write req
            # write in filename
            if check_file_exists(self.filename) == 0:
                new_file = open(self.filename, 'a+')
                #print(self.data)

                out_packet = struct.pack('!hh', 4, self.DATA_block_number)
                print(self.ACK_block_number)
                self.packet_buffer.append(out_packet)
            else:
                error_flag = 1
                self.error_message = "File already exists"
                out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)), 5, 6, self.error_message.encode(),
            byte)
                #print('pack: '+str(out_packet))
                self.packet_buffer.append(out_packet)

        elif in_packet == 3:  # if it's data received,send an ack
            if corruption_flag == 0:
                out_packet = struct.pack('!hh', 4, self.ACK_block_number)
                self.packet_buffer.append(out_packet)

            else:
                # if data is corrupted

                self.error_message = "Not defined: Wrong data,Re-Transmit"
                out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)), 5, 0, self.error_message.encode(),
                                         byte)
                self.packet_buffer.append(out_packet)

        elif in_packet == 4:
            # if it's an acknologement,send the next block of data
           # print(len(chunksBuffer))
            if self.chuncks_buffer_empty() == 0:
                self.data = chunksBuffer.pop(0)
                out_packet = struct.pack('!hh{}s'.format(len(self.data)), 3,
                                         self.DATA_block_number, self.data)
                self.packet_buffer.append(out_packet)
                print('DONE!')
            else:
                print('end')

        elif in_packet == 5:
            # in case of error received
            # check self.errormsg
            # do action considering getting the next packet
            print('red')
        else:
            self.error_message = "   ILLEGAL TFTP OPERATION      "
            out_packet = struct.pack('!hh{}s1b'.format(len(self.error_message)), 5, 4, self.error_message.encode(),
                                     byte)
            self.packet_buffer.append(out_packet)

        # Add the packet to the buffer



    def SplitFileIntoChuncks(self):
        file = open(self.filename, 'rb')
        #print('hiiiiiii')
        while (1):
            chunck = file.read(512)  # reading 512 bytes in each loop
           # print('chuncks :'+str(chunck))
            chunksBuffer.append(chunck)
            if len(chunck) < 512:
                global error_flag
                error_flag = 1
                break
        # print(self.chunksBuffer)

    def _parse_udp_packet(self, packet_bytes):
        global corruption_flag
        corruption_flag = 0
        self.opcode = struct.unpack('>H', packet_bytes[0:2])
        self.opcode = functools.reduce(lambda sub, ele: sub * 10 + ele, self.opcode)
        global error_flag
        if self.opcode == self.TftpPacketType.RRQ.value:
            if error_flag == 1:
                global ACK_flag
                ACK_flag = 1
            print('reading')
            y = 0
            count = 0
            for i in range(2, len(packet_bytes)):
                if packet_bytes[i] == 0:
                    y = i
                    break
            t = y - 2
            for i in range(y + 1, len(packet_bytes)):
                count = count + 1
                if packet_bytes[i] == 0:
                    y = i
                    break
            count = count - 1
            # filename to string
            self.filename = struct.unpack('{}s'.format(t), packet_bytes[2:t + 2])
            self.filename = functools.reduce(operator.add, self.filename)
            self.filename = self.filename.decode("utf-8")
            print(self.filename)
            # mode to string
            self.mode = struct.unpack('{}s'.format(count), packet_bytes[t + 3:count + t + 3])
            self.mode = functools.reduce(operator.add, self.mode)
            self.mode = self.mode.decode("utf-8")
            print(self.mode)
            self.DATA_block_number = 1

        elif self.opcode == self.TftpPacketType.WRQ.value:
            if error_flag == 1:
                 ACK_flag = 1
            print('writing')
            y = 0
            count = 0
            for i in range(2, len(packet_bytes)):
                if packet_bytes[i] == 0:
                    y = i
                    break
            t = y - 2
            for i in range(y + 1, len(packet_bytes)):
                count = count + 1
                if packet_bytes[i] == 0:
                    y = i
                    break
            count = count - 1
            print(packet_bytes[2:t + 2])
            print(packet_bytes[t + 3:count + t + 3])
            self.filename = struct.unpack('{}s'.format(t), packet_bytes[2:t + 2])
            self.filename = functools.reduce(operator.add, self.filename)
            self.filename = self.filename.decode("utf-8")
            print(self.filename)
            self.mode = struct.unpack('{}s'.format(count), packet_bytes[t + 3:count + t + 3])
            self.mode = functools.reduce(operator.add, self.mode)
            self.mode = self.mode.decode("utf-8")
            print(self.mode)
            self.DATA_block_number = 0

        elif self.opcode == self.TftpPacketType.ACK.value:
            print('Acknowledging')
            ACK_flag = 1
            self.ACK_block_number = struct.unpack('>H', packet_bytes[2:4])
            self.ACK_block_number = functools.reduce(lambda sub, ele: sub * 10 + ele, self.ACK_block_number)
            self.DATA_block_number+=1
            print('ACK = '+str(self.ACK_block_number))

        elif self.opcode == self.TftpPacketType.DATA.value:
            if error_flag == 1:
                ACK_flag = 1
            print('Data Packet')
            self.DATA_block_number = struct.unpack('>H', packet_bytes[2:4])
            self.DATA_block_number = functools.reduce(lambda sub, ele: sub * 10 + ele, self.DATA_block_number)
            print('Data block no =' +str(self.DATA_block_number))
            if((self.DATA_block_number-self.ACK_block_number)!=1):
                   #print('hywan'+str(self.ACK_block_number))
                   corruption_flag = 1
            else:
             corruption_flag=0
             self.ACK_block_number = self.DATA_block_number
             print('data block no = '+str(self.DATA_block_number))
             self.data = struct.unpack('{}s'.format(len(packet_bytes) - 4), packet_bytes[4:len(packet_bytes)])
             self.data = functools.reduce(operator.add, self.data)
             self.data = self.data.decode("utf-8")
             wtite_files(self.filename, self.data)
             if len(self.data) < 512:
                global termination_flag
                termination_flag = 1
             print(self.data)

        elif self.opcode == self.TftpPacketType.ERROR.value:
            if error_flag == 1:
               ACK_flag = 1
            print('Error Packet')
            self.error_number = struct.unpack('>H', packet_bytes[2:4])
            self.error_number = functools.reduce(lambda sub, ele: sub * 10 + ele, self.error_number)
            print(self.error_number)
            y = 0
            #print('length of packet = ' + str(len(packet_bytes)))
            if len(packet_bytes) > 4:
                for i in range(4, len(packet_bytes)):
                    if packet_bytes[i] == 0:
                        y = i
                        break
                y = y - 4
                self.error_message = struct.unpack('{}s'.format(y), packet_bytes[4:y + 4])
                self.error_message = functools.reduce(operator.add, self.error_message)
                self.error_message = self.error_message.decode("utf-8")
                print(self.error_message)

        return self.opcode

    def get_next_output_packet(self):

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):  # checks if buffer is empty or not

        return len(self.packet_buffer) != 0

    def chuncks_buffer_empty(self):  # checks if buffer is empty or not
        if len(chunksBuffer) == 0:
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
