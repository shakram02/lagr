import sys
import os
import enum
from socket import *
from struct import *
import time


class TftpProcessor(object):         # ----------> recieves object from server
    """
    Implements logic for a TFTP client.
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

    OPCode = 0
    BlockNumber = 0
    data = ""
    mode = ''
    byte1 = 0
    byte2 = 0
    Ack_State = 0

    class TftpPacketType(enum.Enum):                           # ---------------------> to choose the opcode
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1
        WRQ = 2
        Data = 3
        ACK = 4
        ERROR = 5




    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """

        self.packet_buffer = []
        self.dataListCollection = []
        self.dataToBeSent = []
        self._dataReceived = False
        self._dataBlockNumber = -1
        self.ackReceived = False
        self.ackNumber = -1
        self._errorReceived = False
        self._errorNumber = -1
        self._FileRecieved = False
        self.filename = ""
        self.counter = 0




    #
    # @property
    # def FileRecieved(self):
    #     return self.FileRecieved
    @property
    def dataReceived(self):
        return self._dataReceived
    @property
    def dataBlockNumber(self):
        return self._dataBlockNumber


    @property
    def errorReceived(self):
        return self._errorReceived
    @property
    def errorNumber(self):
        return self._errorNumber

    # @FileRecieved.setter
    # def FileRecieved(self,state):
    #     self._FileRecieved = state
    @dataReceived.setter
    def dataReceived(self, state):
         self._dataReceived = state

    @dataBlockNumber.setter
    def dataBlockNumber(self,Number):
        self._dataBlockNumber = Number




    @errorReceived.setter
    def errorReceived(self,state):
       self._errorReceived = state

    @errorNumber.setter
    def errorNumber(self, Number):
        self._errorNumber = Number











    def process_udp_packet(self, packet_data, packet_source):
         #packetSize = len(packet_data)
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line

        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        # out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        # self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        packetSize = len(packet_bytes)

        if packetSize == 4:
            OriginalData = unpack("HH", packet_bytes)
            print("ACK set True ")
            self.ackReceived = True
            self.ackNumber = OriginalData[1]
            print("ack Number = ", OriginalData[1])


        elif packetSize == 516:
            OriginalData = unpack("HH512s", packet_bytes)
            print("DATA unpacked")
            self.dataListCollection.insert(OriginalData[1],OriginalData[2])
            print("Data Stored To be Written on file")
            self.dataReceived = True
            self.dataBlockNumber = OriginalData[1]
        else:
            #print(type(packedData))
            packetSlice = packet_bytes[0:2]
            packetSliceOpcode = unpack("!H", packetSlice)
            if packetSliceOpcode[0] == 1:
                # This shouldn't be recieved " Create Error Packet and send it to the server "
                self.errorReceived = True
                self.errorNumber(4)
            elif packetSliceOpcode[0] == 2:
                # This shouldn't be recieved " Create Error Packet and send it to the server "
                self.errorReceived = True
                self.errorNumber(4)
            elif packetSliceOpcode[0] == 3:
                # this is data packet
                dataFormat = "!HH{}s".format(packetSize - 4)
                OriginalData = unpack(dataFormat, packet_bytes)
                print("DATA unpacked")
                self.dataListCollection.insert(OriginalData[1],OriginalData[2])
                print("Data Stored To be Written on file")
                self.dataReceived = True
                self.dataBlockNumber = OriginalData[1]
                print("File Completely Recieved")
                self.WriteFileOnDisk()
                self._FileRecieved = True


            elif packetSliceOpcode[0] == 4:  # this also will be error cause the ACK packet size was greater than 4 bytes
                print("ACK Greater than 4 bytes")
                self.errorReceived = True
                self.errorNumber(1)
                # self.ackReceived = True

            elif packetSliceOpcode[0] == 5:
                secondSlice = packet_bytes[0:4]
                packetSliceOpcode = unpack("!HH", secondSlice)

                if packetSliceOpcode[1] == 0:
                    print("Not Defined Error Recieved")
                    print("Processes Terminated By the Client after Recieving Error Message: Try again Later")
                    sys.exit()
                elif packetSliceOpcode[1] == 1:
                    print("file not found Error Recieved")
                    print("Processes Terminated By the Client after Recieving Error Message: Try again Later")
                    sys.exit()
                elif packetSliceOpcode[1] == 2:
                    print("Access Voilation")
                    print("Processes Terminated By the Client after Recieving Error Message: Try again Later")
                    sys.exit()
                elif packetSliceOpcode[1] == 3:
                    print("disk full ")
                    print("Processes Terminated By the Client after Recieving Error Message: Try again Later")
                    sys.exit()
                elif packetSliceOpcode[1] == 4:
                    print("illegal TFTP operation")
                    print("Processes Terminated By the Client after Recieving Error Message: Try again Later")
                    sys.exit()
                elif packetSliceOpcode[1] == 5:
                    print("unknown transfer Id")
                    print("Processes Terminated By the Client after Recieving Error Message: Try again Later")
                    sys.exit()
                elif packetSliceOpcode[1] == 6:
                    print("File ALready Exist")
                    print("Processes Terminated By the Client after Recieving Error Message: Try again Later")
                    sys.exit()
                elif packetSliceOpcode[1] == 7:
                    print("NO SUCH USER")
                    print("Processes Terminated By the Client after Recieving Error Message: Try again Later")
                    sys.exit()



    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        pass


    def CreateDataPackets(self,data,BlockNumber):

            self.OPCode = 3;
            self.BlockNumber = BlockNumber
            self.data = data
            format_str = "!HH{}s".format(len(self.data))
            packedData = pack(format_str,self.OPCode,self.BlockNumber,self.data.encode("ASCII"))
            self.packet_buffer.insert(0, packedData)
            print("Data Packet Created")
            return self.packet_buffer[0]




    def CreateRRQPacket(self,filename):
          OPCode = 1
          filename = filename
          byte1 = 0
          mode = "NETASCII"
          byte2 = 0
          format_str = "!H{}sB{}sB".format(len(filename),len(mode))
          packedData = pack(format_str, OPCode, filename.encode("ASCII"), byte1,mode.encode("ASCII"),byte2)
          self.packet_buffer.insert(0,packedData)
          return self.packet_buffer[0]



    def CreateWRQPacket(self, filename):    # parameter mode
        OPCode = 2
        self.filename = filename
        byte1 = 0
        mode = "NETASCII"
        byte2 = 0
        format_str = "!H{}sB{}sB".format(len(filename),len(mode))
        packedData = pack(format_str, OPCode,filename.encode("ASCII"), byte1, mode.encode("ASCII"),byte2)
        self.packet_buffer.insert(0,packedData)
        #self.packet_buffer.append(packedData)
        return self.packet_buffer[0]





    def CreateAcknowledmentPacket(self,Blocknumber):
        self.OPCode = 4
        self.BlockNumber = Blocknumber
        packedData = pack("!HH", self.OPCode, self.BlockNumber)
        print("Ack generated")
        self.packet_buffer.insert(0,packedData)
        return self.packet_buffer[0]

    def CreateErrorPacket(self,ErrorCode):
         self.OPCode = 5
         self.ErrorCode = ErrorCode
         ErrorDictionary = {0:'Not defined ,see error message (if any)',
                            1:'File not found.',
                            2:'Access Violation',
                            3:'Disk full or allocation exceeded',
                            4:'Illegal TFTP operation',
                            5:'Unknown transfer ID',
                            6:'File already exists',
                            7:'No such user'}
         self.ErrorMessage = ErrorDictionary.get(ErrorCode)
         self.byte1 = 0
         format_str = "!Ii{}sI".format(len(self.ErrorMessage))
         packedData = pack(format_str, self.OPCode, self.ErrorCode, self.ErrorMessage.encode("ASCII"),self.byte1)
         self.packet_buffer.insert(0,packedData)
         print("ERROR Packet Generated")
         return self.packet_buffer[0]





    def _do_some_logic(self, input_packet):       # takes a packet to do some logic on it " will use it to receive packets"
        """
        Example of a private function that does some logic.
        """

       # this is useless




    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())

        Leave this function as is.
        """
        return self.packet_buffer.pop(0)     # from here i know that packet_buffer is the stack to store packets to be sent

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0          # this function checks if there are still avaliable packets to be send


    def request_file(self, file_path_on_server):          # asking to donwload from server RRQ
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        ----------------------------------------------------------------------------------------------------------------
        what this function do is the following :
        1- create an object from the class
        2- create RRQ packet and add it to the stack "buffer" that we have
        3 checks if stack is not empty ,it calls do_socket_logic() to start sending the packet
        4- this function terminate when file is Received "Condition changes when data packet with size less than 512 is Received "
        5- finally it create a file and start writing data to it
        """


        self.CreateRRQPacket(file_path_on_server)
        print("PRQ Created")






    def upload_file(self, file_path_on_server):      # asking to upload to server WRQ
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """

        self.CreateWRQPacket(file_path_on_server)
        print("WRQ Created")

    def listToString(self,lists):


        str1 = ""

        # traverse in the string
        for element in lists:
            element = element.decode("ASCII")
            str1 += element

            # return string
        return str1


    def readFileToChunks(self,filename):
        counter = -1
        file = open(filename, "r")
        ChunkSize = 512
        i = -1
        while True:
            data = file.read(ChunkSize)
            length = len(data)
            counter = counter + 1
            print("Data Packet #", counter)
            # TftpProcessor().dataToBeSent.append(data)
            self.dataToBeSent.insert(counter, data)
            print(length)
            if not data or length != 512:
                self.counter = counter
                file.close()
                break

    def WriteFileOnDisk(self):
        filename = tftp.filename
        with open(filename, "w") as output:
            #string = str(self.dataListCollection)
            string = self.listToString(self.dataListCollection)
            output.write(string)





def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


tftp = TftpProcessor()

def setup_sockets_upload(address,filename):


    print("setup socket upload")

    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    """"this function should recieve address an open a udp connection to the address with port 69"""
    # sending
    s = socket(AF_INET,SOCK_DGRAM)                                      # creating socket object
    server_address = (address,69)
    #s.bind(server_address)
    msg = tftp.CreateWRQPacket(filename)
    tftp.readFileToChunks(filename)
    #if len(TftpProcessor().packet_buffer) != 0:
    s.sendto(msg,server_address)

    packet_data, addressrec = s.recvfrom(1024)
    print("address recieved ",addressrec)
    print("data recieved",packet_data.decode("ascii"))
    if server_address is not addressrec :
            server_address = addressrec
            print("address updated")

    counter = 0
    tftp.process_udp_packet(packet_data, address)
    while True :
        if tftp.ackReceived == True or tftp.counter > counter+1 :
               print("data Packet Created")
               msg = tftp.CreateDataPackets(tftp.dataToBeSent[counter],counter+1)
               counter = counter + 1
               s.sendto(msg, server_address)
               packet_data, address = s.recvfrom(1024)
               tftp.ackReceived = False
               tftp.process_udp_packet(packet_data, address)
        else:
               if tftp.errorReceived == True:

                   error = tftp.errorNumber
                   #don't do any thing
               else:

                print("File Sent")
                break







def setup_sockets_donwload(address,filename):

    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    """"this function should recieve address an open a udp connection to the address with port 69"""
    #
    tftp.filename = filename
    s = socket(AF_INET, SOCK_DGRAM)  # creating socket object
    server_address = (address, 69)
    # s.bind(server_address)
    msg = tftp.CreateRRQPacket(filename)
    # if len(TftpProcessor().packet_buffer) != 0:
    s.sendto(msg, server_address)
    counter = 1
    while True:
        packet_data, addressrec = s.recvfrom(1024)
        print("address recieved ", addressrec)
        print("data recieved", packet_data.decode("ascii"))
        if server_address is not addressrec:
            server_address = addressrec
            print("address updated")

            break

    tftp.process_udp_packet(packet_data, address)

    while True :
            if tftp._FileRecieved == True:
                print("DATA Recieved", counter)
                msg = tftp.CreateAcknowledmentPacket(counter)
                s.sendto(msg, server_address)
                sys.exit()
            elif tftp.dataReceived == True:
               print("DATA Recieved",counter)
               msg = tftp.CreateAcknowledmentPacket(counter)
               counter = counter+1
               s.sendto(msg, server_address)
               packet_data, address = s.recvfrom(1024)
               print(len(packet_data))
               tftp._ackReceived = False
               tftp.process_udp_packet(packet_data, address)
               if len(packet_data) != 516 :
                   print("--->File Recieved Completely")
                   print("Termanated by the client")
                   sys.exit()

               else:
                tftp.process_udp_packet(packet_data, address)
            else:
               if tftp.errorReceived == True:

                   error = tftp.errorNumber
                   #don't do any thing
               else:

                print("ERROR Created # 2")
                break






def do_socket_logic():
    pass



def parse_user_input(address, operation, file_name=None):
    # setup_sockets(address)
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.

    if operation == "push":
        # readFileToChunks(file_name)
        try:
         setup_sockets_upload(address,file_name)
         print(f"Attempting to upload [{file_name}]...")

        except:
            print("File Sent")


    elif operation == "pull":
        # dirname = os.path.abspath(os.curdir)

        setup_sockets_donwload(address,file_name)
        print(f"Attempting to download [{file_name}]...")
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
            exit(-1)    # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")
    #ip_address, operation, file_name = input().split()
    print(ip_address, operation, file_name)
    parse_user_input(ip_address, operation, file_name)

    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    

    # Modify this as needed.



if __name__ == "__main__":
      main()
