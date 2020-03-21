import socket
import sys
import os
import ctypes
import enum
#import numpy
from struct import *
import time
import queue

flag=1
flag_512 = 1
j=0
read_data = []
recieved_address=0
first=0

class TftpProcessor(object):

    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ=2
        DATA=3
        ACK=4
        ERROR=5

    def __init__(self):

      self.packet_buffer = []

    def process_udp_packet(self, packet_data, packet_source,file_name):

        print(f"Received a packet from {packet_source}")

        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet,packet_data,file_name)

        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):

        global flag
        if  packet_bytes[0] ==0 and  packet_bytes[1]==1:
            print("RRQ")
            return 1
        elif  packet_bytes[0] == 0 and packet_bytes[1]==2:
            print("WRQ")
            return 2
        elif packet_bytes[0] == 0 and packet_bytes[1]==3:
            print("DATA")
            return 3
        elif packet_bytes[0] == 0 and packet_bytes[1]==4:
            print("ACK")
            return 4
        elif packet_bytes[0] == 0 and packet_bytes[1]==5:
            print("ERROR")
            flag=0
            return 5
        else:
            return 6




        pass

    def _do_some_logic(self, input_packet,packet_bytes,file_name):
            if input_packet==1 or input_packet==2:
                return self.error_packet()
            if input_packet == 4:
               return self.upload_file(file_name,packet_bytes)


            if input_packet==3:
                return self.request_file(file_name,packet_bytes)

            if input_packet==6:
                return self.error_packet(file_name,packet_bytes)
                #prepare ack packet


    def get_bytes_from_file(self,file_path):
        f = open(file_path,"rb").read()
        return f


    def get_next_output_packet(self):

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):

        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server,packet_bytes):

        global flag
        global flag_512
        global j

        number = packet_bytes[2] + packet_bytes[3]
        opcode1 = bytearray(b'\x00\x04')
        number1 = bytearray([packet_bytes[2]])
        opcode1 = opcode1 + number1
        number2 = bytearray([packet_bytes[3]])
        opcode1 = opcode1 + number2

        global read_data

        i = 0
        for i in range(0, len(packet_bytes)):
            if i == 0:
                continue
            if i % 515 == 0:

                read_data.append(packet_bytes[i - 512:i:])
                #print(read_data)
                flag_512 = 1

        if len(packet_bytes) < 516:
            flag_512 = 0
            read_data.append(packet_bytes[i - (i % 516) : i:])
        j =j +1
        if flag_512 == 0:
            with open('output.txt', 'w') as f:
                f.write("%s\n" % read_data)
            flag = 0
        return opcode1
        pass
    def upload_file(self, file_name,packet_bytes):
        # array of 512s
        global flag
        array = self.get_bytes_from_file(file_name)
        array_512 = []
        i = 0
        for i in range(0, len(array)):
            if i == 0:
                continue
            if i % 512 == 0:
                array_512.append(array[i - 512:i:])
        array_512.append(array[i - (i % 512): i:])
        number = bytes([packet_bytes[2]])
        number3 = bytes([packet_bytes[3]])
        number = number + number3
        iter= int.from_bytes(number, byteorder='big', signed=False)  + 1
        opcode1 = bytearray(b'\x00\x03')
        number2 = iter.to_bytes(2,'big')
        opcode1 = opcode1 + number2
        array1 = bytearray(array_512[iter-1])
        if len(array_512[iter-1])<512:
            flag=0
        opcode1 = opcode1 + array1
        return opcode1
    def error_packet(self,file_name,input_packet):
        opcode = bytearray(b'\x00\x05')
        bytesArray1 = bytearray(b'\x00\x04')
        opcode = opcode + bytesArray1
        opcode = opcode + bytearray(b'\x00')
        bytesArray1 = bytearray("Illegal TFTP operation.", 'ASCII')
        opcode = opcode + bytesArray1
        opcode = opcode + bytearray(b'\x00')
        return opcode

def setup_sockets():
    server_address = ("127.0.0.1", 69)
    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP

    return sock,server_address


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass
def parse_user_input(address, operation, file_name):

    global  flag
    global recieved_address
    global first
    sock,server_address = setup_sockets()
    p1 = TftpProcessor()

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        opcode = bytearray(b'\x00\x02')
        bytesArray1 = bytearray("test.txt", 'ASCII')
        opcode = opcode + bytesArray1
        opcode = opcode + bytearray(b'\x00')
        bytesArray1 = bytearray("octet", 'ASCII')
        opcode = opcode + bytesArray1
        opcode = opcode + bytearray(b'\x00')
        sock.sendto(opcode, address)
        while flag:

            bytes, address = sock.recvfrom(512)
            if first == 0:
                recieved_address = address
                first = 1
                p1.process_udp_packet(bytes, address, file_name)
                if p1.has_pending_packets_to_be_sent():
                    packet = p1.get_next_output_packet()
                    sock.sendto(packet, address)
            else:
                if recieved_address!=address:
                    continue
                else:
                    p1.process_udp_packet(bytes, address, file_name)
                    if p1.has_pending_packets_to_be_sent():
                        packet = p1.get_next_output_packet()
                        sock.sendto(packet, address)

    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        opcode = bytearray(b'\x00\x01')
        bytesArray1 = bytearray(file_name, 'ASCII')
        opcode = opcode + bytesArray1
        opcode = opcode + bytearray(b'\x00')
        bytesArray1 = bytearray("octet", 'ASCII')
        opcode = opcode + bytesArray1
        opcode = opcode + bytearray(b'\x00')
        sock.sendto(opcode, address)

        while flag:

            bytes, address = sock.recvfrom(516)
            if first == 0:
                recieved_address = address
                first = 1
                p1.process_udp_packet(bytes, address, file_name)
                if p1.has_pending_packets_to_be_sent():
                    packet = p1.get_next_output_packet()
                    sock.sendto(packet, address)
            else:
                if recieved_address != address:
                    continue
                else:
                    p1.process_udp_packet(bytes, address, file_name)
                    if p1.has_pending_packets_to_be_sent():
                        packet = p1.get_next_output_packet()
                        sock.sendto(packet, address)
    return sock

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
            exit(-1)    # Program execution failed.

def main():

    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)
    ip_address = get_arg(1)
    operation = get_arg(2)
    file_name = get_arg(3)

    server_address = ("127.0.0.1", 69)

    parse_user_input(server_address, operation, file_name)


if __name__ == "__main__":
    main()

