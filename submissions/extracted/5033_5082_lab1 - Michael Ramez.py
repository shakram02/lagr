# Don't forget to change this file's name before submission.
import sys
import os
import enum

import  socket
import sys
from struct import *

class TftpProcessor(object):

    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5



    def __init__(self,is_download):
        self.Block_no = is_download
        self.packet_buffer = []
        pass
    
    def process_udp_packet_upload(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")
        # temp=unpack("!hh", packet_source)
        if unpack("!h", packet_data[:2])[0] == 4:
            ack_format = "!hh"
            packet = unpack(ack_format, packet_data)

            if packet[1] == self.Block_no:
                self.Block_no+=1
                return 1
            while self.has_pending_packets_to_be_sent():
                self.packet_buffer.pop()
            self.packet_buffer.append(self.ERROR(0, "incorrect block number").serialize())
            print("incorrect block number")
            return 0

        elif unpack("!h", packet_data[:2])[0] == 5:
            error_format = "!hh{}sh".format(len(packet_data[4:len(packet_data) - 2]))
            packet = unpack(error_format, packet_data)
            print(packet[2].decode("utf-8"))

        else:
            while self.has_pending_packets_to_be_sent():
                self.packet_buffer.pop()
            self.packet_buffer.append(self.ERROR(0, "malformed packet").serialize())
            print("malformed packet")
            return 0

    

    def process_udp_packet(self, packet_data, packet_source, f):
        self.file = f
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        if in_packet[0] == 5:
            f.close()
            os.remove(f.name)
            return 0
        out_packet = self._do_some_logic(in_packet)
        self.Block_no = self.Block_no + 1
        # This shouldn't change.
        self.packet_buffer.append(out_packet)

        if len(in_packet[2]) == 512 and in_packet[0] == 3:
            return 1
        return 0


    def _parse_udp_packet(self, packet_bytes):
        if unpack("!h", packet_bytes[:2])[0] == 3:
            data_format = "!hh{}s".format(len(packet_bytes[4:]))
            packet = unpack(data_format, packet_bytes)
            self.file.write(packet[2])

        elif unpack("!h", packet_bytes[:2])[0] == 5:
            error_format = "!hh{}sh".format(len(packet_bytes[4:len(packet_bytes) - 2]))
            packet = unpack(error_format, packet_bytes)
            print(packet[2].decode("utf-8"))
        else:
            packet = 0
        return packet

    def _do_some_logic(self, input_packet):
        if input_packet[0] == 3:
            return self.ACK(self.Block_no).serialize()
        return self.ERROR(0, "malformed packet").serialize()

    def get_next_output_packet(self):

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        self.packet_buffer.append(self.RRQ(file_path_on_server, "Octet").serialize())
        pass

    def upload_file(self, file_path_on_server):
        self.packet_buffer.append(self.WRQ(file_path_on_server, "Octet").serialize())
        pass

    class ACK:
        Opcode = 4

        def __init__(self, Block_number):
            self.Block_number = Block_number

        def serialize(self):
            format_str = "!hh"
            return pack(format_str, self.Opcode, self.Block_number)
    
    def ack(self,block_no):
        self.packet_buffer.append( self.ACK(block_no).serialize() )


    class ERROR:
        def __init__(self, error_code, error_msg):
            # self.Opcode = Opcode
            self.Opcode = 5
            self.error_code = error_code
            self.error_msg = error_msg

        def serialize(self):
            format_str = "!hh{}s?".format(len(self.error_msg))
            return pack(format_str, self.Opcode, self.error_code, self.error_msg.encode("ASCII"), 0)

    def error(self,error_code,error_msg):
        self.packet_buffer .append(self.ERROR(error_code,error_msg).serialize())

    class RRQ:
        Opcode = 1
        Byte_1 = 0
        Byte_2 = 0

        def __init__(self, Filename, Mode):
            self.Filename = Filename
            self.Mode = Mode

        def serialize(self):
            format_str = "!h{}s?{}s?".format(len(self.Filename), len(self.Mode))
            return pack(format_str, self.Opcode, self.Filename.encode("ASCII"), self.Byte_1, self.Mode.encode("ASCII"),
                        self.Byte_2)




    class WRQ:
        def __init__(self, Filename, Mode):
            # self.Opcode = Opcode
            self.Opcode = 2
            self.Filename = Filename
            # self.Byte_1 = Byte_1
            self.Byte_1 = 0
            self.Mode = Mode
            # self.Byte_2 = Byte_2
            self.Byte_2 = 0

        def serialize(self):
            format_str = "!h{}s?{}s?".format(len(self.Filename), len(self.Mode))
            return pack(format_str, self.Opcode, self.Filename.encode("ASCII"), self.Byte_1, self.Mode.encode("ASCII"),self.Byte_2)


    class DATA:
        def __init__(self, Block_number, DATA):
            self.Opcode = 3
            self.Block_number = Block_number
            self.DATA = DATA

        def serialize(self):
            format_str = "!hh{}s".format(len(self.DATA))
            return pack(format_str, self.Opcode, self.Block_number, self.DATA)


    def data(self,Block_number,DATA):
        self.packet_buffer.append(self.DATA(Block_number,DATA).serialize())


        
    def quantize(self,fileName):
        try:
            f=open(fileName,"rb")
        except:
            print("File not found")
            self.packet_buffer.pop(0)
            return
        arr=f.read()
        n=len(arr)
        n=int(n/512)
        for i in range(n):
            self.packet_buffer.append(self.DATA(i+1,arr[i*512:i*512+512]).serialize())
            pass
        self.packet_buffer.append(self.DATA(n+1,arr[n*512:-1]).serialize())
        f.close()
        


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def parse_user_input(address, operation, file_name=None):

    my_soket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_soket.settimeout(5)
    
    server_address = (address, 69)

    if operation == "push":
        tftp = TftpProcessor(0)
        print(f"Attempting to upload [{file_name}]...")
        tftp.upload_file(file_name)
        tftp.quantize(file_name)
        try:
            while tftp.has_pending_packets_to_be_sent() :
                my_soket.sendto(tftp.get_next_output_packet() , server_address)
                data, server_address = my_soket.recvfrom(516)
                if not tftp.process_udp_packet_upload(data,server_address):
                     break

            if tftp.has_pending_packets_to_be_sent() :
                my_soket.sendto(tftp.get_next_output_packet() , server_address)

        except socket.timeout as e:
            print(e)
    
    elif operation == "pull":
        tftp = TftpProcessor(1)
        tftp.request_file(file_name)
        bool=1
        my_soket.sendto(tftp.get_next_output_packet(),server_address)
        f = open(file_name, "wb")
        try:
            while bool :

                data, server = my_soket.recvfrom(516)
                bool = tftp.process_udp_packet(data, server, f) and tftp.has_pending_packets_to_be_sent()
                if bool:
                    my_soket.sendto(tftp.get_next_output_packet(), server)

        except socket.timeout as e:
            print(e)
        print(f"Attempting to download [{file_name}]...")
        f.close()

        pass
    my_soket.close()

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

    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
