# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct

class TftpProcessor(object):

    class TftpPacketType(enum.Enum):
    	RRQ = 1
    	WRQ = 2
    	DATA= 3
    	ACK = 4
    	ERROR = 5

    def __init__(self):
        # self.packet_type =TftpPacketType()
        self.packet_buffer = []
        self.filepath=''
        self.downloadedFile=''
        self.lastAck=False
        self.lastData=False
        self.emptyDataPacket=False
        #0 state for upload
        #1 state for download
        self.state=0
        self.previous_packet=0
        pass

    def process_udp_packet(self, packet_data, packet_source):
    	print(f"Received a packet from {packet_source}")
    	in_packet, block_number = self._parse_udp_packet(packet_data)
    	out_packet = self._do_some_logic(in_packet, block_number, packet_data)
    	# This shouldn't change.
    	self.packet_buffer.append(out_packet)


    def _parse_udp_packet(self,packet_bytes):
        type = struct.unpack('!b',packet_bytes[1:2])[0]
        if type == 3:
            block_number = struct.unpack( '!h', packet_bytes[2:4])[0]
            format_str = "!{}s".format( len(packet_bytes) - 4)
            new_data = struct.unpack(format_str, packet_bytes[4::])[0]
            self._printToFile(block_number,new_data)
            return self.TftpPacketType.DATA, block_number
        elif type == 4:
            block_number = struct.unpack( '!h', packet_bytes[2:4])[0]
            return self.TftpPacketType.ACK, block_number
        elif type == 5:
            errorCode = struct.unpack('!h',packet_bytes[2:4])[0]
            errorMsg = struct.unpack('!{}s'.format(len(packet_bytes)-5),packet_bytes[4:len(packet_bytes)-1])[0]
            print("[CLIENT] [ERROR] [",errorCode,']',errorMsg.decode("utf-8") )
            return self.TftpPacketType.ERROR,0

    def _validate_input_packet(self, input_type, input_packet, block_number):
        if self.state == 0 :
            if not (input_type == self.TftpPacketType.ACK or input_type == self.TftpPacketType.ERROR ):
                return False
        elif self.state == 1:
            if not(input_type  == self.TftpPacketType.DATA or input_type == self.TftpPacketType.ERROR) :
                return False

        print('Block Number received ', self.previous_packet)
        if input_type == self.TftpPacketType.ACK and len(input_packet) != 4:
            return False
        if block_number != self.previous_packet:
            return False
        if input_type == self.TftpPacketType.DATA and len(input_packet) <4:
            return False
        self.previous_packet = self.previous_packet + 1

        return True

    def _do_some_logic(self, input_type, block_number, packet):
        correct_response = self._validate_input_packet(input_type, packet, block_number)
        if not correct_response:
            return self.create_err_packet()
        if input_type == self.TftpPacketType.ACK:
            return self._parse_file( block_number)
        elif input_type == self.TftpPacketType.DATA:
            return self._create_ack_packet( block_number)
        elif input_type == self.TftpPacketType.ERROR:
            return 'ERR'
        

    def get_next_output_packet(self):
    	return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
    	"""
    	Returns if any packets to be sent are available.
    	Leave this function as is.
    	"""
    	return len(self.packet_buffer) != 0

    def _process_chunk(self,chunk,block_no):
        format_str = "!bbh{}s".format(len(chunk))
        packet = struct.pack(format_str,0,self.TftpPacketType.DATA.value,block_no,chunk)
        return packet

    def _create_ack_packet(self, block_no):
    	format_str = "!bbh"
    	packet = struct.pack(format_str,0, self.TftpPacketType.ACK.value, block_no)
    	return packet

    def create_err_packet(self):
        format_str="!bbh23sb"
        packet = struct.pack(format_str,0,self.TftpPacketType.ERROR.value,4,'Illegal TFTP operation.'.encode('utf-8'),0)
        return packet

    def _create_request_packet(self,type,file_name):
        format_str = "!bb{}sb5sb".format(
                len(file_name))
        packet = struct.pack( format_str,0,type.value,file_name.encode('utf-8'),0,'octet'.encode('utf-8'),0)
        return packet

    def _printToFile(self,block_no,data):
        self.downloadedFile.write(data)
        if len(data)<512:
            self.lastAck=True
            self.downloadedFile.close()

    def _parse_file(self,block_no):
        chunk_len=512
        with open(self.filepath,'rb') as file:
            file.seek( block_no * chunk_len)
            chunk=file.read(chunk_len)

            if not chunk and self.emptyDataPacket==True:
                chunk=b''
                self.emptyDataPacket=False
            elif not chunk:
                self.lastData=True

            packet_chunk=self._process_chunk(chunk, block_no+1)
        return packet_chunk

    def upload_file(self, file_path_on_server):
        len=os.stat(file_path_on_server).st_size
        if len%512==0:
            self.emptyDataPacket=True

        self.filepath=file_path_on_server
        packet=self._create_request_packet(self.TftpPacketType.WRQ,file_path_on_server)
        self.packet_buffer.append(packet)
        pass

    def request_file(self, file_path_on_server):
        self.filepath=file_path_on_server
        self.downloadedFile = open(file_path_on_server, 'wb+')
        packet=self._create_request_packet(self.TftpPacketType.RRQ,file_path_on_server)
        self.packet_buffer.append(packet)
        self.state=1
        pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
    	print(f"[WARN] File name is invalid [{script_name}]")
    pass


def socket_connection( original_server_address, client_socket, file_name,processor):
    packet = processor.get_next_output_packet()
    client_socket.sendto(packet, (original_server_address, 69))
    input_packet, server_address = client_socket.recvfrom(516)
    processor.process_udp_packet(input_packet, server_address)

    while True:
        if processor.has_pending_packets_to_be_sent():
            packet = processor.get_next_output_packet()
            if processor.lastData== True :
                # if(processor.multipleOf512==True):
                #     emptyPacket= struct.pack('!bbh',0,3,)
                #     client_socket.sendto(emptyPacket, server_address)
                print("[CLIENT] Data Uploaded Successfully ")
                break
            elif packet=='ERR':
                break
            elif processor.lastAck == True:
                client_socket.sendto(packet, server_address)
                print("[CLIENT]  Data Downloaded Successfully")
                break
            client_socket.sendto( packet, server_address)
            try:
                client_socket.settimeout(5.0)
                input_packet, input_address = client_socket.recvfrom(516)
            except:
                client_socket.sendto(packet, server_address)
                client_socket.settimeout(5.0)
                input_packet, input_address = client_socket.recvfrom(516)

            maximum_iterations = 5
            while input_address != server_address and maximum_iterations > 0:
                client_socket.sendto(processor.create_err_packet(), input_address)
                client_socket.settimeout(5.0)
                input_packet, input_address = client_socket.recvfrom(516)
                maximum_iterations = maximum_iterations - 1
            if maximum_iterations == 0:
                print(' Could not complete transaction because of invalid input packets')
                break

            processor.process_udp_packet(input_packet, input_address)

        else :
            break

def parse_user_input(address, operation, file_name=None):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    processor = TftpProcessor()
    if operation == "push":
    	processor.previous_packet = 0 #first acknowledge that will be received should be 0
    	processor.upload_file( file_name )
    elif operation == "pull":
    	processor.previous_packet = 1 #first data pack that will be received should be 1
    	processor.request_file( file_name )
    	print(f"Attempting to download [{file_name}]...")
    socket_connection( address, client_socket, file_name, processor)


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
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
