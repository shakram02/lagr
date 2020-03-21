# Don't forget to change this file's name before submission.
import sys
import os
import enum
import struct
import socket
from threading import Thread,Event
from multiprocessing import Process,Manager,Queue
import time

class TftpProcessor(object):

    class TftpPacketType(enum.IntEnum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5
    class TftpState(enum.IntEnum):
        Idle = 1
        WaitingToDownload = 2
        Downloading = 3
        WaitingToUpload = 4
        Uploading = 5
        Error = 6

    def __init__(self):
        self.packet_buffer = []
        self.state = TftpProcessor.TftpState.Idle
        self.data = []
        self.block_number = 0
        self.filename = ''
        pass

    def process_udp_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)
        if(out_packet !=  None):
            self.packet_buffer.append(out_packet)


    def make_error_packet(self,error_code):
        error_msg=''
        print('Make Error Packet with code: '+str(error_code))
        self.state=TftpProcessor.TftpState.Error
        if(error_code==1):
            error_msg='Malformed Packet'
        elif (error_code == 4):
            error_msg = 'Illegal TFTP operation'
        elif(error_code==5):
            error_msg='Unknown transfer ID'
        fmt='!' + 'hh' + str(len(error_msg)) + 's' +'b'
        self.packet_buffer.append(struct.pack(fmt,TftpProcessor.TftpState.Error,error_code,error_msg.encode('utf-8'),0))


    def _parse_udp_packet(self, packet_bytes):
        try:
            type = struct.unpack('!h', packet_bytes[0:2])[0]
            if type == TftpProcessor.TftpPacketType.DATA:

                block_num = struct.unpack('!h', packet_bytes[2:4])[0]
                data_len = packet_bytes.__len__() - 4
                fmt = '!' + str(data_len) + 's'
                data = list(struct.unpack(fmt, packet_bytes[4:packet_bytes.__len__()])[0])
                print('Packet Type: DATA with block ' + str(block_num))
                l=[]
                l.append(type)
                l.append(block_num)
                l.append(data)
                return l
            elif type == TftpProcessor.TftpPacketType.ACK:
                print('Packet Type: ACK')
                block_num = struct.unpack('!h', packet_bytes[2:4])[0]
                l=[]
                l.append(type)
                l.append(block_num)
                return l
            elif type == TftpProcessor.TftpPacketType.ERROR:
                print('Packet Type: ERROR')
                error_code = struct.unpack('!h', packet_bytes[2:4])[0]
                error_msg = ''
                i = 4
                buffer = struct.unpack('!b', packet_bytes[i:i + 1])[0]
                while buffer != 0:
                    error_msg += chr(buffer)
                    i += 1
                    buffer = struct.unpack('!b', packet_bytes[i:i + 1])[0]
                print(error_msg)
                exit(0)
            else:
                self.make_error_packet(1)
        except:
            self.make_error_packet(1)
        pass


    def _do_some_logic(self, input_packet):
        if input_packet == None:
            return
        if input_packet[0]==TftpProcessor.TftpPacketType.DATA:
            if self.block_number +1 == input_packet[1]:
                self.block_number+=1
                self.data+=input_packet[2]
                if(len(input_packet[2])<512):
                    print('file complete')
                    f = open(self.filename,"wb")
                    f.write(bytearray(self.data))
                    self.data=[]
                    self.state=TftpProcessor.TftpState.Idle
                return struct.pack('!hh',TftpProcessor.TftpPacketType.ACK,input_packet[1])
            else:
                self.make_error_packet(4)

        pass
    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        fmt= '!' + 'h' + str(len(file_path_on_server)) + 's'+'b' + str( len('octet')) + 's' +'b'
        self.filename=file_path_on_server
        self.state=TftpProcessor.TftpState.Downloading
        self.packet_buffer.append(struct.pack(fmt,TftpProcessor.TftpPacketType.RRQ,file_path_on_server.encode('utf-8'),0,b'octet',0 ))
        pass

    def upload_file(self, file_path_on_server):

        f=open(file_path_on_server, "rb")
        i=1
        self.packet_buffer=[]
        while True:
            buffer = f.read(512)
            fmt = '!' + 'hh' + str(len(buffer)) + 's'
            self.packet_buffer.append(struct.pack(fmt,3,i,buffer))
            if(len(buffer)<512):
                break
            i+=1
        fmt = '!' + 'h' + str(len(file_path_on_server)) + 's'+'b' + str(len('octet')) + 's'+'b'
        return struct.pack(fmt,TftpProcessor.TftpPacketType.WRQ,file_path_on_server.encode('utf-8'),0,b'octet',0 )
        pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def do_socket_logic(s,packet,address,is_finalPacket,output):
    s.sendto(packet,address)
    if(not is_finalPacket):
        print("waiting")
        output.put(s.recvfrom(516))
    output.put((None,None))
    pass

def call_Process(s,packet,address,is_finalPacket):
    output=Queue()
    i=1
    send_process = Process(target=do_socket_logic, args=(s,packet,address,is_finalPacket,output))
    send_process.start()
    send_process.join(timeout=5)
    while send_process.is_alive():
        send_process.terminate()
        if i>2:
            print('Max resend times,Connection will be terminated')
            sys.exit()

        print('Ack Wait timeout , resend last packet')
        send_process = Process(target=do_socket_logic, args=(s,packet,address,is_finalPacket,output))
        i+=1
        send_process.start()
        send_process.join(timeout=5)
    return output.get()


def parse_user_input(address, operation, file_name=None):
    tftp_processor = TftpProcessor()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        sent_packet = tftp_processor.upload_file(file_name)
        received_packet_data, server_address = call_Process(s,sent_packet, server_address, False)
        tftp_processor.process_udp_packet(received_packet_data, server_address)
        while tftp_processor.has_pending_packets_to_be_sent():
            if tftp_processor.TftpState==TftpProcessor.TftpState.Error:
                s.sendto(tftp_processor.get_next_output_packet(),server_address)
                exit(0)
            received_packet_data, received_address = call_Process(s,tftp_processor.get_next_output_packet(), server_address,False)
            if received_address[1] !=server_address[1]:
                tftp_processor.make_error_packet(2)
                s.sendto(tftp_processor.get_next_output_packet(),received_address)
                continue
            tftp_processor.process_udp_packet(received_packet_data, server_address)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        tftp_processor.request_file(file_name)
        while tftp_processor.has_pending_packets_to_be_sent():
            if tftp_processor.state==TftpProcessor.TftpState.Error:
                s.sendto(tftp_processor.get_next_output_packet(),server_address)
                sys.exit()
            packet = tftp_processor.get_next_output_packet()
            is_finalPacket = tftp_processor.state == TftpProcessor.TftpState.Idle
            packet_data, received_address = call_Process(s,packet, server_address, is_finalPacket)
            if packet_data != None and received_address[1] !=server_address[1] and server_address[1]!=69:
                tftp_processor.make_error_packet(2)
                s.sendto(tftp_processor.get_next_output_packet(), received_address)
                continue
            server_address=received_address
            if (packet_data != None):
                tftp_processor.process_udp_packet(packet_data, server_address)
        pass


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

    operation = get_arg(1, "push")
    file_name = get_arg(2, "photopp.jpg")
    ip_address = get_arg(3, "127.0.0.1")

    parse_user_input(ip_address, operation, file_name)

if __name__ == "__main__":
    main()
