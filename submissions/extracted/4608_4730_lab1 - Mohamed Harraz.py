import sys
import os
import enum
import socket
import struct 
import threading
import time
import asyncio
import _thread


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

    def __init__(self,packSize:int):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.isProcessing = True
        self.hasError = False
        self.fileName = ""
        self.packSize = packSize
        self.clientUploading = False
        self.packet_buffer = []
        self.store_buffer = []
        self.file_data = []
        self.last_block_sent = 0

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
        #print(f"Received data is: {packet_data}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)
        # This shouldn't change.
        if out_packet != None:
             self.packet_buffer.append(out_packet)
    
    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        opcode = self.TftpPacketType((packet_bytes[0] << 8) | (packet_bytes[1]))
        if opcode == self.TftpPacketType.RRQ:
            filename,mode = self._parseRRQ(packet_bytes)
            return [opcode, filename , mode]
        elif  opcode == self.TftpPacketType.WRQ:
            filename,mode = self._parseWRQ(packet_bytes)
            return [opcode, filename , mode]
        elif  opcode == self.TftpPacketType.ACK:
            blockNumber = self._parseACK(packet_bytes)
            return [opcode, blockNumber]
        elif  opcode == self.TftpPacketType.DATA:
            blockNumber,data = self._parseDATA(packet_bytes)
            return [opcode, blockNumber , data]
        elif opcode == self.TftpPacketType.ERROR:
            errorCode,errorMessage = self._parseERROR(packet_bytes)
            print(f"Recieved Error code: {errorCode} message: {errorMessage}")
            self.hasError = True
            self.isProcessing = False
            return [opcode,errorCode,errorMessage]
        else:
            return [opcode]
            

    def _parseRRQ(self, packet_bytes):
        fileName = ""
        iterator = 2
        while packet_bytes[iterator] != 0x00:
            fileName+=chr(packet_bytes[iterator])
            iterator = iterator + 1
        iterator = iterator + 1 #ignore the empty space
        mode = ""
        while packet_bytes[iterator] != 0x00:
            mode += chr(packet_bytes[iterator])
            iterator = iterator + 1
        return [fileName,mode]

    def _parseWRQ(self, packet_bytes):
        self.clientUploading = True
        fileName = ""
        iterator = 2
        while packet_bytes[iterator] != 0x00:
            fileName += chr(packet_bytes[iterator])
            iterator = iterator + 1
        iterator = iterator + 1 #ignore the empty space
        mode = ""
        while packet_bytes[iterator] != 0x00:
            mode += chr(packet_bytes[iterator])
            iterator = iterator + 1
        return [fileName,mode]
            


    def _parseACK(self, packet_bytes):
        opcode,nblock = struct.unpack("!HH",packet_bytes)
        return [nblock]

    def _parseDATA(self, packet_bytes):
        opcode,nblock,data = struct.unpack("!HH" + str(len(packet_bytes) - 4) + "s",packet_bytes)
        return [nblock,data]
        

    def _parseERROR(self, packet_bytes):
        errMessage = ""
        errorCode = (packet_bytes[2] << 8) | (packet_bytes[3])
        if len(packet_bytes) > 4:
            iterator = 4
            while packet_bytes[iterator] != 0x00:
                fileName += chr(packet_bytes[iterator])
                iterator = iterator + 1
            iterator = iterator + 1 #ignore the empty space
            print(errorCode,errMessage)
            self.isProcessing = False
            self.hasError = True
        return [errorCode,errMessage]

    def read_from_file(self):
        #bytearray readed from file in readed file data array named
        #store_buffer
        file = open(self.fileName, "rb")
        buffer = list(file.read(self.packSize))
        self.file_data.append(buffer)
        while len(buffer) == self.packSize:
            buffer = list(file.read(self.packSize))
            self.file_data.append(buffer)
        file.close()

    def _do_some_logic(self, input_packet):
        if input_packet[0] == self.TftpPacketType.WRQ:
               #first WRQ reply with ACK is with blknumber = 0
               self.fileName = input_packet[1]
               if os.path.exists(self.fileName):
                 self.hasError = True
                 error_message = "File already exists."
                 self.isProcessing = False
                 return struct.pack("!HH{}sB".format(len(error_message)),5,6,error_message.encode("ASCII"),0)
               else:
                 return struct.pack("!HH",4,0)
        elif input_packet[0] == self.TftpPacketType.DATA:
            self.store_buffer.append(input_packet[2])
            self.isProcessing = len(input_packet[2]) == self.packSize
            return struct.pack("!HH",4,input_packet[1])
        elif input_packet[0] == self.TftpPacketType.RRQ:
            self.fileName = input_packet[1]
            if os.path.exists(self.fileName):
                self.read_from_file()
                self.last_block_sent += 1
                return struct.pack("!HH",3,1) + bytearray(self.file_data[0])
            else:
                self.isProcessing = False
                error_message = "File not found!"
                return struct.pack("!HH{}sB".format(len(error_message)),5,1,error_message.encode("ASCII"),0)
        elif input_packet[0] == self.TftpPacketType.ACK:
            self.isProcessing = len(self.file_data) > self.last_block_sent
            if self.isProcessing:
                if input_packet[1][0] - self.last_block_sent == 0:
                    self.last_block_sent += 1
                    pack = struct.pack("!HH",3,self.last_block_sent) + bytearray(self.file_data[self.last_block_sent-1])
                    return pack
                else:
                    self.isProcessing = False
                    self.hasError = True
                    error_message = "Illegal TFTP operation!"
                    return struct.pack("!HH{}sB".format(len(error_message)), 5, 4, error_message.encode("ASCII"), 0)
            else:
               return None
        elif input_packet[0] == self.TftpPacketType.ERROR:
                self.isProcessing = False
                return None
        else:
             error_message = "Not defined, see error message (if any)"
             return struct.pack("!HH{}sB".format(len(error_message)), 5, 0, error_message.encode("ASCII"), 0)



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

    def endStream(self):
        #end stream is to destruct the TFTP Processor and write the file if
        #something was uploaded.
        file = open(self.fileName, 'wb')
        for i in range(0,len(self.store_buffer)):
               file.write(self.store_buffer[i])
        file.close()




def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address,port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, port)
    server_socket.bind(server_address)
    return server_socket


def listenForMessage(server_socket,size):
    packet = server_socket.recvfrom(size)
    return packet
    
def sendMessage(server_socket,destination,data):
    try:
        server_socket.sendto(data,destination)
    except:
        print("Destination Unreachable !")



def processAndSend(TFTPproc,inPacket,socket):
        TFTPproc.process_udp_packet(inPacket[0],inPacket[1])
        if TFTPproc.has_pending_packets_to_be_sent() :
         outPacket = TFTPproc.get_next_output_packet()
         sendMessage(socket,inPacket[1],outPacket)

def handleClient(inPacket):
     TFTPproc = TftpProcessor(512)
     server_socket_new = setup_sockets(sys.argv[1],0)
     processAndSend( TFTPproc,inPacket,server_socket_new)
     while TFTPproc.isProcessing :
            inPacket = listenForMessage(server_socket_new,1024) # enough size to read 512 bytes of data + protocol data
            processAndSend(TFTPproc,inPacket,server_socket_new)
     if ~TFTPproc.hasError & TFTPproc.clientUploading :
               TFTPproc.endStream()
     server_socket_new.close()


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
    ip_address = sys.argv[1]
    # Make a new socket object.
    
    
    # Bind tells the OS to allocate this address for this process.
    # Clients don't need to call bind since the server doesn't
    # care about their address.  But clients must know where the
    # server is.
    server_socket_listen = setup_sockets(sys.argv[1],69)
   
    while True:
        inPacket = listenForMessage(server_socket_listen,1024) # enough size to read 512 bytes of data + protocol data
        #thread = handleClient(inPacket)
        #thread.start()
        _thread.start_new_thread(handleClient, (inPacket,))

        #thread.start_new_thread( handleClien, (inPacket, ) )
        #_thread.start_new_thread(handleClient,inPacket)
        #handleClient(inPacket)
       

if __name__ == "__main__":
    main()