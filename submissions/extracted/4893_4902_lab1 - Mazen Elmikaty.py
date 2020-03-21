import socket
import sys
import os
import numpy as np


#this will be the download request sent from the client to the server.

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.setblocking(0)
client_socket.settimeout(15)

class TftpProcessor(object):
    
    
    def upload_file(self,fileName, server_address):
    
        #we read the file and turn file into blocks each of size 512 bytes and and put them in a list
        block_list, number_of_blocks = self._parse_file(fileName);
    
        #creating write request
        wrq_packet = self._create_wrq_packet(fileName, 'octet')
        #sending write request to server
        client_socket.sendto(wrq_packet, server_address)
    
        #recieving ack packet from server
        block_number = 0
    
        while number_of_blocks != 0:
            packet = client_socket.recvfrom(100)
            ack_packet,server_port_address = packet
            opcode = ack_packet[1]
            if opcode == 4:
                #create data packet
                data_packet = bytearray()
                # first 2 bytes are for opcode
                data_packet.append(0)
                data_packet.append(3)
                
                #Second 2 bytes for block number
                block_number+=1
                data_packet = data_packet + block_number.to_bytes(2,'big')
                #the block to be sent
                data_packet = data_packet + block_list[block_number-1]
            
                client_socket.sendto(data_packet,server_port_address)
                number_of_blocks-=1
            elif opcode == 5:
                error_msg = data_packet[4:]
                print('Error:',error_msg.decode('ASCII'))
                sys.exit()
            print(f"[{fileName}] upload complete")
        
    def request_file(self,fileName, server_address):
    
        #creating rrq packet
        rrq_packet = self._create_rrq_packet(fileName, 'octet')
        
        #After the packet is created it it sent to the server
        client_socket.sendto(rrq_packet, server_address)
    
        #the client then expects either a data packet or an error packet
        last_packet_flag = False
        file_data = bytearray()
        while last_packet_flag == False:
            packet = client_socket.recvfrom(516)
            data_packet, server_port_address = packet
        
        
            opcode = data_packet[1]
            if opcode == 3: #data packet
                block_number = data_packet[2:4]
                file_data = file_data + data_packet[4:]
                ack_packet = self._create_ack_packet(block_number)
                client_socket.sendto(ack_packet, server_port_address)
            
        
            elif opcode == 5: #error packet
                #error_code = data_packet[2:4]
                error_msg = data_packet[4:]
                print('Error:',error_msg.decode('ASCII'))
                sys.exit()
        
            #checking if it is last packet recieved
            if len(data_packet) < 516:
                last_packet_flag = True
            
        
        fp = open(fileName,'w',newline = '')
        fp.write(file_data.decode('ASCII'))
        fp.close()
        print(f"[{fileName}] download complete")

    def _create_wrq_packet(self,file_name, mode = 'octet'):
        wrq_packet = bytearray()
        #first 2 bytes are for opcode and is equal to 1 for rrq packet
        wrq_packet.append(0)
        wrq_packet.append(2)
        
        #we add file name to the packet and end it with a 0 byte
        file_name = bytearray(file_name,'ASCII')
        wrq_packet = wrq_packet + file_name
        wrq_packet.append(0)
    
        #we add mode which is octet and end it with a 0 byte
        mode = bytearray('octet','ASCII')
        wrq_packet = wrq_packet + mode
        wrq_packet.append(0)
    
        return wrq_packet

    def _create_rrq_packet(self,file_name, mode = 'octet'):
        #create read request packet
        rrq_packet = bytearray()
        #first 2 bytes are for opcode and is equal to 1 for rrq packet
        rrq_packet.append(0)
        rrq_packet.append(1)
    
        #we add file name to the packet and end it with a 0 byte
        file_name = bytearray(file_name,'ASCII')
        rrq_packet = rrq_packet + file_name
        rrq_packet.append(0)
    
        #we add mode which is octet and end it with a 0 byte
        mode = bytearray(mode,'ASCII')
        rrq_packet = rrq_packet + mode
        rrq_packet.append(0)
    
        return rrq_packet

    def _create_ack_packet(self,block_number):
        ack_packet = bytearray()
        #first 2 bytes are for opcode and is equal to 4 for ack packet
        ack_packet.append(0)
        ack_packet.append(4)
    
        #second 2 bytes for block_number that has been recieved
        ack_packet += block_number
        return ack_packet

    def _parse_file(self,file_name):
        """
        This function read the file and divides the data into blocks
        of size 512 bytes and returns a list of blocks and the number of blocks
        in the list
        """
        #read the hole file
        try:
            fp = open(file_name,'r')
            file_data = fp.read()
        except FileNotFoundError:
            print("Error: File not Found")
            sys.exit()
            fp.close()
    
        #turn file data into blocks of size 512 bytes each
        file_data = bytearray(file_data,'ASCII')
        file_size = len(file_data)
        number_of_blocks = int(np.ceil(file_size/512))
        block_list = []
        for i in range(0,number_of_blocks):
            block_list.append(file_data[512*i:512*(i+1)])
    
        block_list.append(file_data)
    
        return block_list, number_of_blocks
    

def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    

    


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code. 
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    
    server_address = (address,69)
    proc = TftpProcessor()
    
    
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        proc.upload_file(file_name, server_address)
        
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        proc.request_file(file_name, server_address)
        


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplied, it tries to use a default value.
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
    file_name = get_arg(3, "file.txt")
    
    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()


