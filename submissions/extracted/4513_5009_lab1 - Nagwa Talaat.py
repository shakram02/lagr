import sys

import os
import socket
import enum





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



    def __init__(self):

       self.ip = "127.0.0.1"
       self.port = 69
       self.Buffer = 512
       self.data_list = []
       self.index = -1
       opcode =0
       self.opcode = opcode
       self.server_address
       self.server_socket
       self.retsocket
       self.bytes=[]
       self.client_address
       self.zero_counter
       self.filename
       self.temp
       self.index
       i = 0
       self.block_number = i + 1





        """

        Add and initialize the *internal* fields you need.

        Do NOT change the arguments passed to this function.



        Here's an example of what you can do inside this function.

        """

        self.packet_buffer = []

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

        in_packet = self._parse_udp_packet(packet_data)

        out_packet = self._do_some_logic(in_packet)



        # This shouldn't change.

        self.packet_buffer.append(out_packet)



    def _parse_udp_packet(self, packet_bytes):

        """

        You'll use the struct module here to determine

        the type of the packet and extract other available

        information.

        """

        pass



    def _do_some_logic(  server_socket, struct,Buffer,data_list):
        retsocket = do_socket_logic()
        bytes, client_address = retsocket.recvfrom(512)
        zero_counter=1
other

        while zero_counter in range (2, len(bytes)):
            if bytes[zero_counter] == 0:
                break

        filename = bytes[2:zero_counter]
        if bytes[1] == 1:
             print("READ REQUEST")
             has_pending_packets_to_be_sent(filename, Buffer, data_list)
             download_request(filename, client_address, server_socket, retsocket, struct)

        else:
            print("WRITE REQUEST")
            upload_command(filename, client_address, retsocket, struct)

    def send_packet(retsocket,block_number,filename):
        B_n = 0
        block_number = B_n
        f = open(filename, "wb")
        bytes, client_address_temp = retsocket.recvfrom(516)
        f.write(bytes[4:])
        block_number = block_number + 1

    def get_next_output_packet(struct,retsocket,client_address,filename,block_number):
        op =3
        opcode=op
        Ackn=0
        while 1:
            send_packet(retsocket, block_number, filename)
            packets = struct.pack("!HH", opcode, block_number)
            packet = packets
            retsocket.sendto(packet, client_address)
            if len(bytes) < 516:
                print("UPLOAD COMPLETED")
                break
        Ackn= Ackn+1
        if Ackn ==1:
        print("Download completed ")
        main()



        return self.packet_buffer.pop(0)

    def download_request(filename,client_address,server_socket,retsocket,struct):
      ind = -1
      index = ind
      data_list = []
      Buf = 512
      Buffer =Buf
other

      f = open(filename, "rb")
      while 1:
        temp = f.read(Buffer)
        if not temp:
         break
        index = index + 1
        data_list.append(temp)

      opcode = 3
      for i in range(index + 1):
        block_number = i + 1
        format_str = "!HH{}s".format(len(data_list[i]))
        packet = struct.pack(format_str, opcode, block_number, data_list[i])
        retsocket.sendto(packet, client_address)
        bytes, client_address_temp = server_socket.recvfrom(512)
        receievd_block_number = struct.unpack("!H", bytes[2:4])
        if bytes[1] != 4 or receievd_block_number[0] != block_number:
            print("ERROR: IN THE ACK")

      f.close()
      print("DOWNLOAD COMPLETED")
      main()

    def has_pending_packets_to_be_sent(filename,Buffer,data_list):
        count=0
        f = open(filename, "rb")
        x = True
        for y in x:
            temp = f.read(Buffer)
            if not temp:
                break
            index = index + 1
            data_list.append(temp)
            count=count+1
        """

        Returns if any packets to be sent are available.



        Leave this function as is.

        """

        return (count) != 0





def check_file_name(filename):

    script_name = os.path.basename(filename)

    import re

    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)

    if not matches:

        print(f"[WARN] File name is invalid [{script_name}]")

    pass








def do_socket_logic():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ip = "127.0.0.1"
    port = 69
    server_address = (ip, port)
    server_socket.bind(server_address)
    print("[SERVER] Socket info:", server_socket)
    return server_socket











def upload_command(filename,client_address,retsocket,struct):
    print("WRITE REQUEST")
    op=4
    opcode = op
    b_n =0
    block_number = b_n
    packets = struct.pack("!HH", opcode, block_number)
    packet = packets
    retsocket.sendto(packet, client_address)

    f = open(filename, "wb")
    get_next_output_packet(struct,retsocket,client_address,filename)









def main():
    retsocket = do_socket_logic()
    bytes, client_address = retsocket.recvfrom(512)

    for zero_counter in range(2, len(bytes)):
        if bytes[zero_counter] == 0:
            break

    filename = bytes[2:zero_counter]









    # This argument is required.

    # For a server, this means the IP that the server socket

    # will use.

    # The IP of the server.

    ip_address = get_arg(1, "127.0.0.1")

    setup_sockets(ip_address)





if __name__ == "__main__":

    main()








    def check_file_name(filename):

         script_name = os.path.basename(filename)

         import re

         matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)

         if not matches:

          print(f"[WARN] File name is invalid [{script_name}]")

          pass








