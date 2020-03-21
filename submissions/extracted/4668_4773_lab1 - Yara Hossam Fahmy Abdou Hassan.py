import socket
import sys
import os
import enum
import struct
import functools
import select

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("127.0.0.1", 69)
dest_address = []



class TftpProcessor(object):

    class TftpPacketType(enum.Enum):

        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):

        self.block_no = 0
        self.packet_buffer = []
        self.data=[]
        self.ErrorString=""
        self.ErrorFlag=0
        self.chunks_List=[]
        self.chunks_List_length=0
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        this function is used to prcoess a packet received from the server
        by parsing it (calls parse function) and do the corresponding action
        """
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        #adding the response to the buffer to be sent to server
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        #extracts the opcode from the bytearray to know the required operation
        opcode_test = struct.unpack('<1s', packet_bytes[1:2]) #type is tuple
        opcode = functools.reduce(lambda sub, ele: sub * 10 + ele, opcode_test) #type is byte

        if opcode == b'\x01':
            return "RRQ"
        elif opcode == b'\x02':
            return "WRQ"
        elif opcode == b'\x03':
            self.data = packet_bytes[4:] # extracts the data from the packet recieved
            return "DATA"
        elif opcode == b'\x04':
            print("Ack: Block no  ")
            print(self.block_no)
            return "ACK"
        elif opcode == b'\x05':
            self.ErrorFlag=1
            temp = packet_bytes[4:-1] #extracts the error message to print it to the user later
            self.ErrorString=temp.decode("utf-8") #converting the extracted error msg to a string
            return "ERROR"

    pass

    def _do_some_logic(self, input_packet):

        if input_packet == "RRQ":
            return
        elif input_packet == "WRQ":
            return
        elif input_packet == "DATA":
            #if the recieved packet was a data packet so the client will respond by sending acknowledgment
            client_response = bytearray()
            #the ack opcode
            client_response.append(0)
            client_response.append(4)
            #ack block number
            self.block_no = self.block_no + 1
            client_response.append(0)
            client_response.append(self.block_no)
            #return the acknowledment packet
            return client_response

        elif input_packet == "ACK":
           #if the received packet was acknowledgment, the client will repond by sending data packet
            if int(self.block_no) < self.chunks_List_length:
                client_response = bytearray()
              #data opcode
                client_response.append(0)
                client_response.append(3)
              #data block number
                client_response.append(0)
                client_response.append(self.block_no + 1)
                #data itself
                data_block = self.chunks_List[self.block_no]
                client_response += data_block

                self.block_no= self.block_no+1

                print("DATA: Block ")
                print(self.block_no)
                return client_response

        elif input_packet == "ERROR":
            print(self.ErrorString)

            client_response = bytearray()
            # the ack opcode
            client_response.append(0)
            client_response.append(4)
            # ack block number
            client_response.append(0)
            client_response.append(0)

            return client_response

        pass

    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        #this function is to write the request file from server (download)
        file = open(file_path_on_server, 'ab')
        file.write(self.data)
        pass

    def upload_file(self, file_path_on_server):
        #this function is to read the file to be uploaded  to the server
      f = open(file_path_on_server, 'rb')
      while True:
        chunk = f.read(512)   #reading 512 blocks of data from the file
        if not chunk: break
        self.chunks_List.append(chunk)

     #to know the length of the file
      self.chunks_List_length = len(self.chunks_List)
      pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", address)
    pass

def parse_user_input(address, operation, file_name=None):
    #this function is for parsing the input to know the required operation
    obj = TftpProcessor()

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        if not os.path.isfile(file_name):
            #if the file is not found; so we'll send an error packet to the server bec file cant be uploaded
            print("ERROR:FILE NOT FOUND")
            client_response = bytearray()
            client_response.append(0)
            client_response.append(5)  #error code
            client_response.append(0)
            client_response.append(1)  #file not found code
            error_m="File not found."
            error_message=bytearray(error_m.encode('utf-8')) #encoding the error message &converting to bytearray
            client_response +=error_message
            client_response.append(0)
            client_socket.sendto(client_response, server_address)

        else: #file exists, so upload it
         obj.upload_file(file_name)
         Client_packet(2, file_name)  # 2 -- write index
         while True:
             client_socket.setblocking(0)
             ready = select.select([client_socket], [], [], 10)
             if ready[0]:
                server_packet = client_socket.recvfrom(4096)
                data, address = server_packet
                dest_address.append(address)
                if not address == dest_address[0]:
                    client_response = bytearray()
                    client_response.append(0)
                    client_response.append(5)  # error code
                    client_response.append(0)
                    client_response.append(5)  # Unknown transfer ID.
                    error_m = "Unknown transfer ID."
                    error_message = bytearray(
                        error_m.encode('utf-8'))  # encoding the error message &converting to bytearray
                    client_response += error_message
                    client_response.append(0)
                    client_socket.sendto(client_response, address)
                    obj.process_udp_packet(data, dest_address[0])

                else:
                 obj.process_udp_packet(data, address)
                 if obj.ErrorFlag == 0:
                     temp_packet = obj.get_next_output_packet()
                     client_socket.sendto(temp_packet, address)
                     if len(temp_packet) < 516:
                         break
                 else:
                     temp_packet = obj.get_next_output_packet()
                     client_socket.sendto(temp_packet, address)
                     exit(0)
             else:
                 print("Request Timeout")




    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        if os.path.isfile(file_name):
            print("ERROR:FILE ALREADY EXISTS") #trying to download an existing file
            client_response = bytearray()
            client_response.append(0)
            client_response.append(5) #error code
            client_response.append(0)
            client_response.append(6) #file exists code
            error_m="File already exists."
            error_message=bytearray(error_m.encode('utf-8'))
            client_response +=error_message
            client_response.append(0)
            client_socket.sendto(client_response, server_address)

        else:
         Client_packet(1, file_name)

         while True:
            client_socket.setblocking(0)
            ready = select.select([client_socket], [], [], 10)
            if ready[0]:
              server_packet = client_socket.recvfrom(516)
              data, address = server_packet
              dest_address.append(address)
              if not address == dest_address[0]:
                  client_response = bytearray()
                  client_response.append(0)
                  client_response.append(5)  # error code
                  client_response.append(0)
                  client_response.append(5)  # Unknown transfer ID.
                  error_m = "Unknown transfer ID."
                  error_message = bytearray(
                  error_m.encode('utf-8'))  # encoding the error message &converting to bytearray
                  client_response += error_message
                  client_response.append(0)
                  client_socket.sendto(client_response, address)
                  obj.process_udp_packet(data, dest_address[0])

              else:
               obj.process_udp_packet(data, address)
               if obj.ErrorFlag == 0:
                obj.request_file(file_name)
                temp_packet = obj.get_next_output_packet()
                client_socket.sendto(temp_packet, address)
               else:
                   temp_packet = obj.get_next_output_packet()
                   client_socket.sendto(temp_packet, address)
                   exit(0)
               if len(obj.data) < 512:
                    break
            else:
                 print("Request Timeout")
pass


def Client_packet(index, name):
    client_response = bytearray()
    if index == 1:

        client_response.append(0)
        client_response.append(1) # read request opcode

    elif index == 2:
        client_response.append(0)
        client_response.append(2) # write request opcode

    filename = bytearray(name.encode('utf-8')) #append the required file name
    client_response += filename
    client_response.append(0) #0 indicating the end of filename
    mode= bytearray(bytes('octet', 'utf-8')) #the required mode
    client_response += mode
    client_response.append(0) #0 indicating end of mode
    client_socket.sendto(client_response, server_address)


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


def main():

    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)


    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
