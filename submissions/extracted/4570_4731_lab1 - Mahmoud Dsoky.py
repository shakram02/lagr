import sys
import os
import enum
import socket
import struct
import math
from functools import partial
from math import ceil


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
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.filename = ""
        self.mode = ""
        #self.cnt = 0
        self.filesize = ""
        self.blocknumber=0
        self.opcode=""


        pass

    def getopcode(self,packet, x):
        #print(packet)
        opcode = struct.unpack('!H', packet[:2])[0]
        if opcode == x:
            return True
        return False

    def download(self,client_address,information_socket):
        s="!hh"
        #data=''
        if os.path.isfile(self.filename)==True:
            errmsg = bytearray()

            i = 0
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            i = 5
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            i = 0
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            i = 6
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            errstr = "File already exists.".encode()
            errmsg = errmsg + errstr
            i = 0
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            information_socket.sendto(errmsg, client_address)
            exit(0)
        w= open(self.filename, "wb")
        for i in range (0,self.blocknumber):
            temp = struct.pack(s, 4, i)
            #print("helloo",temp)
            information_socket.sendto(temp, client_address)
            packet = information_socket.recv(1024)
            if self.getopcode(packet, 3) == False:
                i = 0
                firstcode = i.to_bytes(1, byteorder='big')
                errmsg = errmsg + firstcode
                i = 5
                firstcode = i.to_bytes(1, byteorder='big')
                errmsg = errmsg + firstcode
                i = 0
                firstcode = i.to_bytes(1, byteorder='big')
                errmsg = errmsg + firstcode
                i = 4
                firstcode = i.to_bytes(1, byteorder='big')
                errmsg = errmsg + firstcode
                errstr = "Illegal TFTP operation.".encode()
                errmsg = errmsg + errstr
                i = 0
                firstcode = i.to_bytes(1, byteorder='big')
                errmsg = errmsg + firstcode
                information_socket.sendto(temp, client_address)
                exit(0)
            #print(chr(packet[5]))
            #data=packet[4:]
            w.write(packet[4:])
            # for j in range(4, len(packet)):
            #     data+=chr(packet[j])
            #     #print(data)
            #     w.write(data.encode())
        w.close()


            #print(packet)



    # #def download(self,client_address,information_socket):
    #     #acknowlageport = information_socket.getsockname()
    #     # s = "!hh"
    #     # temp = struct.pack(s, 4,self.blocknumber)
    #     # frame =b'\x00\x04'
    #     # j=0
    #
    #     w = open("risho/" + self.filename, "wb")
    #     for i in range(0 , self.blocknumber):
    #         num=i%256
    #         #j.to_bytes(2, byteorder='big')
    #         #num.to_bytes(2, byteorder='big')
    #         frame = b'\x00\x04'
    #         frame=frame+j.to_bytes(1,'big')+num.to_bytes(1,'big')
    #
    #         if i%256 ==0 and i>0:
    #             j=j+1
    #         print(frame)
    #         information_socket.sendto(frame, client_address)
    #         packet = information_socket.recv(555)
    #
    #         #data, address = packet
    #         data=""
    #         for i in range(4,len(packet)):
    #             data+=chr(packet[i])
    #         #print(data)
    #
    #         #print (type(packet))
    #         #line=bytearray(data)
    #         w.write(data.encode())
    #     w.close()



    def upload(self,client_address,information_socket):
        #acknowlageport = information_socket.getsockname()

        try:
            filesize=os.path.getsize(self.filename)
            blocknumbers=math.ceil(filesize/512)
            #print(filesize)
            #print(blocknumbers)
            with open(self.filename, 'rb') as openfileobject:

                uplaodarr=bytearray()
                for chunk in iter(partial(openfileobject.read, 512), b''):
                    uplaodarr=uplaodarr+chunk
                openfileobject.close()
            s="!hh512s"
            temp=struct.pack(s,3,1,uplaodarr[0:512])
            #frame=b'\x00\x03'
            #j=1
            #frame=frame+j.to_bytes(1,'big')+uplaodarr[0:512]
            #print(frame)
            information_socket.sendto(temp, client_address)

            for i in range(1,blocknumbers):
                ack = information_socket.recvfrom(1024)
                if self.getopcode(ack[0], 4) == False:
                    i = 0
                    firstcode = i.to_bytes(1, byteorder='big')
                    errmsg = errmsg + firstcode
                    i = 5
                    firstcode = i.to_bytes(1, byteorder='big')
                    errmsg = errmsg + firstcode
                    i = 0
                    firstcode = i.to_bytes(1, byteorder='big')
                    errmsg = errmsg + firstcode
                    i = 4
                    firstcode = i.to_bytes(1, byteorder='big')
                    errmsg = errmsg + firstcode
                    errstr = "Illegal TFTP operation.".encode()
                    errmsg = errmsg + errstr
                    i = 0
                    firstcode = i.to_bytes(1, byteorder='big')
                    errmsg = errmsg + firstcode
                    information_socket.sendto(temp, client_address)
                    exit(0)
                ack=ack[0]
                #print(ack)
                numberofblock=int.from_bytes((ack[2:]), byteorder='big')+1

                if i !=blocknumbers-1:
                    s = "!hh" + str(len(uplaodarr[(int(numberofblock) - 1) * 512:(int(numberofblock) * 512)])) + "s"
                    data =struct.pack(s,3,numberofblock,uplaodarr[(int(numberofblock)-1)*512:(int(numberofblock)*512)])
                    #print(data)
                #data+=data+numberofblock.to_bytes(1,'big')+
                else :
                    s = "!hh" + str(len(uplaodarr[(int(numberofblock) - 1) * 512:])) + "s"
                    data = struct.pack(s, 3, numberofblock,uplaodarr[(int(numberofblock) - 1) * 512:])

                information_socket.sendto(data, client_address)

            information_socket.close()






                #for i in range(1, self.blocknumber):

                 #   frame = frame + i.to_bytes(1, 'big')+uplaodarr[(i - 1)*512: i*512]







                #print(uplaodarr[:512])


        except IOError:
            errmsg = bytearray()

            i = 0
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            i = 5
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            i = 0
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            i = 1
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            errstr = "File not found.".encode()
            errmsg = errmsg + errstr
            i = 0
            firstcode = i.to_bytes(1, byteorder='big')
            errmsg = errmsg + firstcode
            information_socket.sendto(errmsg, client_address)

            print("File not accessible")
            exit(0)







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

        #print(packet_bytes)
        self.opcode = struct.unpack('!H', packet_bytes[:2])[0]


        for x in range(2, len(packet_bytes)):
            if packet_bytes[x] == 0:
                cnt = x
                break
            else:
                self.filename += chr(packet_bytes[x])

        for x in range(cnt + 1, len(packet_bytes)):
            if packet_bytes[x] == 0:
                cnt = x
                break
            else:
                self.mode += chr(packet_bytes[x])

        #print(self.opcode)
        #print(self.filename)
        #print(self.mode)
        for x in range(cnt + 1, len(packet_bytes)):
            if packet_bytes[x] == 0:
                cnt = x
                break;
        for x in range(cnt + 1, len(packet_bytes)):
            if packet_bytes[x] == 0:
                cnt = x
                break;
        for x in range(cnt + 1, len(packet_bytes)):
            if packet_bytes[x] == 0:
                cnt = x
                break;
        for x in range(cnt + 1, len(packet_bytes)):
            if packet_bytes[x] == 0:
                cnt = x
                break;
            else:
                self.filesize += chr(packet_bytes[x])
        #print("file size = " + self.filesize)

        self.blocknumber= math.ceil(int(self.filesize) / 512)
        #print(self.blocknumber)

        pass
        if self.opcode==2:#if write request
            return 2
        if self.opcode==1:#if read request
            return 1


    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        pass
        return 0

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


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """
    # don't forget, the server's port is 69 (might require using sudo on Linux)
    print(f"TFTP server started on on [{address}]...")
    pass


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    pass


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
    setup_sockets(ip_address)

    # Make a new socket object.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Note that this address must be specified in the client.

    server_address = ("127.0.0.1", 69)  # 69 port of tp

    # Bind tells the OS to allocate this address for this process.
    # Clients don't need to call bind since the server doesn't
    # care about their address. But clients must know where the
    # server is.
    server_socket.bind(server_address)
    print("[SERVER] Socket info:", server_socket)
    print("[SERVER] Waiting...")
    # This line of code will "Block" the execution of the program.
    packet = server_socket.recvfrom(1024)
    data, client_address = packet
    print("[SERVER] IN", data)
    print(data)
    TftpProcessorobject1 = TftpProcessor()
    mode=TftpProcessorobject1._parse_udp_packet(data)
    if mode==2:
        TftpProcessorobject1.download(client_address,server_socket)
    if mode==1:
        TftpProcessorobject1.upload(client_address,server_socket)




if __name__ == "__main__":
    main()
