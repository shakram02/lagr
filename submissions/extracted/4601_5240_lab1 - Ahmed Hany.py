# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct
import math
class TftpProcessor(object):
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        self.packet_buffer = []
        self.File_Size = 0
        self.Block_Size= 0
        self.File_Name = ""
        self.TID = ""
        self.MyIP = ""
        pass

    def process_udp_packet(self, packet_data, packet_source):

        print(f"Received a packet from {packet_source}")
        self._parse_udp_packet(packet_data)
        MyType = self.TftpPacketType(packet_data.__getitem__(1))
        self.TID = packet_source
        if MyType == self.TftpPacketType.WRQ:
            print("I want to write something please")
            self._do_some_logic_Download(packet_data)
        elif MyType == self.TftpPacketType.RRQ:
            print("I Want to Read Something Please")
            self._do_some_logic_Upload(packet_data)
        #elif MyType == self.TftpPacketType.DATA:
        #elif MyType == self.TftpPacketType.ACK:
        elif MyType == self.TftpPacketType.ERROR:
            self._do_some_logic_Error(packet_data)
        else:
            print("Error Code 0!!")
            self._Error_Handling(0)

    def _parse_udp_packet(self,packet_bytes):
        Passer = packet_bytes.split(b'\0')
        self.File_Size = int(Passer[6])
        self.Block_Size = int(Passer[4])
        self.File_Name = Passer[1][1:].decode()
        pass
    def _Error_Handling(self,ErrorCode):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.MyIP, 0))
        Error_MSG = ""
        Error_Packet = b'\x00\x05\x00'
        Hany = 0
        if ErrorCode == 0:
            Error_MSG = "Not defined, see error message (if any)."
        if ErrorCode == 4:
            Error_MSG = "Illegal TFTP operation."
        elif ErrorCode == 1:
            Error_MSG = "File not found."
        elif ErrorCode == 6:
            Error_MSG = "File already exists."
        Error_Packet = Error_Packet + ErrorCode.to_bytes(1, 'big') + Error_MSG.encode() + Hany.to_bytes(1, 'big')
        server_socket.sendto(Error_Packet, self.TID)
        exit(0)
        pass
    def _do_some_logic_Download(self,input_packet):
        server_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        server_socket.bind((self.MyIP,0))
        Number_Of_Blocks = math.ceil(self.File_Size/self.Block_Size)
        IP,PORT=self.TID
        if os.path.isfile("Server_Downloads/" + self.File_Name):
            print("Error Code 6!!")
            self._Error_Handling(6)
        H = open("Server_Downloads/" + self.File_Name, "wb")
        Hany = 0
        Maher = 0
        for i in range(0,Number_Of_Blocks):
            if Hany == 256:
                Maher = Maher + 1
                Hany = 0

            Passer = b'\x00\x04' + Maher.to_bytes(1,'big')
            Block_Number_Byte = Hany.to_bytes(1,'big')
            Passer = Passer + Block_Number_Byte
            server_socket.sendto(Passer,self.TID)
            Passer = server_socket.recv(555)
            if Passer.__getitem__(1) == 3:
                H.write(Passer[4:])
                Hany = Hany +1
            else:
                Data , Source = Passer
                print("Error Code 4!!")
                self._Error_Handling(4)
                server_socket.close()

        server_socket.close()
        main()
        pass

    def _do_some_logic_Error(self, input_packet):
        Error_Code = input_packet[2:4]
        Error_Msg = input_packet[4:(len(input_packet)-1)]
        print("Error_Code = " + Error_Code + " , " + Error_Msg)
        pass
    def _do_some_logic_Upload(self,input_packet):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.MyIP, 0))
        Server_IP,Server_PORT = server_socket.getsockname()
        Client_IP, Client_PORT = self.TID
        try:
            H = open("Server_Files/" + self.File_Name,"rb")
        except:
            print("Error Code 1!!")
            self._Error_Handling(1)
        Passer = H.read(512)
        while len(Passer)==512:
         self.packet_buffer.append(Passer)
         Passer = H.read(512)
        self.packet_buffer.append(Passer)
        Hany = 1
        Maher = 0
        while self.has_pending_packets_to_be_sent():
         if Hany == 256:
            Maher = Maher + 1
            Hany = 0
         Output_Packet = b'\x00\x03' + Maher.to_bytes(1,'big') + Hany.to_bytes(1,'big') + self.get_next_output_packet()
         server_socket.sendto(Output_Packet,self.TID)
         Response = server_socket.recv(555)
         if Response.__getitem__(1) != 4 :
            print("Error Code 4!!")
            self._Error_Handling(4)
         if Response.__getitem__(2).to_bytes(1,'big') == Maher.to_bytes(1,'big') :
            if Response.__getitem__(3).to_bytes(1,'big') == Hany.to_bytes(1,'big') :
                Hany = Hany + 1
        server_socket.close()
        main()
        pass
    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass

def setup_sockets(Address):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("Socket successfully created")
    UDP_PORT = 69  # port
    server_socket.bind((Address, UDP_PORT))
    print("socket binded to %s" % (UDP_PORT))
    print("[SERVER] Socket info:", server_socket)
    print("[SERVER] Waiting...")
    Packet = server_socket.recvfrom(512)
    return Packet
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
    Test = TftpProcessor()
    Test.MyIP = get_arg(1, "127.0.0.1")
    Packet = setup_sockets(Test.MyIP)
    Data, Client_Address = Packet
    Test.process_udp_packet(Data,Client_Address)
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)


if __name__ == "__main__":
    main()