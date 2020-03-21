# Don't forget to change this file's name before submission.
import sys
import os
import enum
import struct
import socket

class TftpProcessor(object):
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5
    def __init__(self):
        self.block_data_read = 1
        self.block_data_write = 1
        self.Read = True
        self.Write = True
        self.end_ack = True
        self.end_data = True
        self.file =[]
        self.filename = ""
        self.file_data = []
        self.packet_buffer = []
        pass
    def process_udp_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = None
        if in_packet[0] == 1 and self.Read:
            self.filename = in_packet[1]
            if self.check_file_read()!=True:
                out_packet = self.apply_error(1, "File not found.")
            else:
                self.Read = False
                self.read_file(in_packet[1])
                out_packet = self._do_some_logic_read(in_packet)
        elif in_packet[0] == 2 and self.Write:
            self.filename = in_packet[1]
            if self.check_file_write()!= True:
                out_packet = self.apply_error(6, "File already exists.")
            else:
                self.Write = False
                out_packet = self._do_some_logic_write(in_packet)
        elif in_packet[0] == 3:
            self.file_data.append(in_packet[2])
            if len(in_packet[2]) < 512:
                self.end_ack = False
            out_packet = self._do_some_logic_data(in_packet)
        elif in_packet[0] == 4:
            out_packet = self._do_some_logic_ack(in_packet)
        elif in_packet[0] == 5:
            print("Error recieved from the client")
        elif in_packet[0] == 6:
            out_packet = self.apply_error(4, "Illegal TFTP operation.")
        else:
            out_packet = self.apply_error(0, "Invalid flow of request")
        if out_packet != None:
            self.packet_buffer.append(out_packet)
    def check_file_read(self):
       # print(self.filename)
        if os.path.isfile(self.filename):
           return True
           #return self.apply_error(6, "File already exists.")
        return False
    def check_file_write(self):
        if os.path.isfile(self.filename):
           return False
           #return self.apply_error(6, "File already exists.")
        return True
    def read_file(self, filename):
        file = open(filename, "rb")
        data = file.read(512)
        while len(data) != 0:
            self.file_data.append(data)
            data = file.read(512)
    def _parse_udp_packet(self, packet_bytes):
        list = []
        opcode = struct.unpack('!H', packet_bytes[:2])[0]
        if opcode == self.TftpPacketType.RRQ.value:
            list.append(1)
            packet = packet_bytes.split(b'\0')[:-1]
            filename = packet[1].decode()[1:]
            mode = packet[2].decode()
            list.append(filename)
            list.append(mode)
            return list
        elif opcode == self.TftpPacketType.WRQ.value:
            packet = packet_bytes.split(b'\0')[:-1]
            filename = packet[1].decode()[1:]
            mode = packet[2].decode()
            list.append(2)
            list.append(filename)
            list.append(mode)
            return list
        elif opcode == self.TftpPacketType.DATA.value:
            list.append(3)
            block_num_byte = packet_bytes[2:4]
            block_num = struct.unpack('!H', block_num_byte)[0]
            data = packet_bytes[4:]
            list.append(block_num)
            list.append(data)
            return list
        elif opcode == self.TftpPacketType.ACK.value:
            list.append(4)
            block_num = struct.unpack('!H', packet_bytes[2:])[0]
            list.append(block_num)
            return list
        elif opcode == self.TftpPacketType.ERROR.value:
            list.append(5)
            error_num = struct.unpack('!H', packet_bytes[2:4])[0]
            list.append(error_num)
            error_msg = packet_bytes[4:len(packet_bytes) - 1].decode()
            list.append(error_msg)
            return list
        else:
            list.append(6)
            return list
        pass
    def _do_some_logic_write(self, input_packet):
        packet_byte = struct.pack("!HH", 4, 0)
        return packet_byte
    def _do_some_logic_data(self, input_packet):
        if self.block_data_write != input_packet[1]:
            return self.apply_error(0, "Error in block number")
        self.block_data_write+=1
        packet_byte = struct.pack("!HH", 4, input_packet[1])
        return packet_byte
    def _do_some_logic_ack(self,input_packet):
        packet_byte = struct.pack("!HH", 3, input_packet[1] + 1)
        if self.has_pending_file_data_to_be_sent():
            packet_byte = packet_byte + self.get_next_output_file_data()
            if len(packet_byte) < 516:
                self.end_data = False
            return packet_byte
    def _do_some_logic_read(self, input_packet):
        if self.has_pending_file_data_to_be_sent():
            pack = struct.pack("!HH", 3, 1)
            pack = pack + self.get_next_output_file_data()
            return pack
    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)
    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0
    def get_next_output_file_data(self):
        self.file.append(self.file_data[0])
        return self.file_data.pop(0)
    def has_pending_file_data_to_be_sent(self):
        return len(self.file_data) != 0
    def write_file(self):
        file = open(self.filename, "wb")
        while len(self.file_data) !=0 :
            file.write(self.file_data.pop(0))
        file.close()
    def apply_error(self, ErrorCode, ErrorMsg):
        print(ErrorCode,ErrorMsg)
        pack = struct.pack("!HH", self.TftpPacketType.ERROR.value, ErrorCode)
        pack = pack + ErrorMsg.encode() + b'\x00'
        return pack
def ack_signal(self):
    return self.end_ack
def isfinished(self):
    return  self.end_data and self.end_ack
def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass
def setup_sockets(address):
    print(f"TFTP server started on on [{address}]...")
def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.
def main():
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)
    ip_address = get_arg(1, "127.0.0.1")
    setup_sockets(ip_address)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (ip_address, 69)
    server_socket.bind(server_address)
    print("[SERVER] Socket info:", server_socket)
    print("[SERVER] Waiting...")
    tftp_processor = TftpProcessor()
    while True:
        data, address = server_socket.recvfrom(5000)
        #print("Received: %s, from: %s" % (data, address))
        if not isfinished(tftp_processor):
            tftp_processor = TftpProcessor()
        tftp_processor.process_udp_packet(data, address)
        if tftp_processor.has_pending_packets_to_be_sent():
            out_packet = tftp_processor.get_next_output_packet()
            server_socket.sendto(out_packet, address)
        if ack_signal(tftp_processor) == False:
            tftp_processor.write_file()
            tftp_processor = TftpProcessor()
if __name__ == "__main__":
    main()