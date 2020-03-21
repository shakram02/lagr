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
        DATA = 3
        ACK = 4
        
    def __init__(self):

        self.packet_buffer = []

        # To save data from/to file
        self.data_buffer = []

        self.block_number_uploaded_data = 0
        self.block_number_downloaded_data = 0
        self.has_pending_data_to_be_received = True

        pass

    def process_udp_packet(self, packet_data, packet_source):

        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_data):

        # returning true if the packet is ack
        # returning false if the packet is data

        if packet_data[0:2] == b'\x00\x04':
            return True
        elif packet_data[0:2] == b'\x00\x03':
            self.block_number_downloaded_data = struct.unpack("!h", packet_data[2:4])[0]

            # Stop receiving data from the server when the packet data size less the 512 bytes.
            if len(packet_data[4:]) < 512:
                self.has_pending_data_to_be_received = False

            # Adding data to the data buffer.
            self.data_buffer.append(packet_data[4:])
            return False

        # Data transfer termination: the error message is shown in the console
        else:
            print('>> Error: ' + packet_data[4:-2].decode('utf-8'))
            exit(-1)

    def _do_some_logic(self, is_ack_packet):

        if is_ack_packet:  # Creating the packet of the uploaded data
            data = self.data_buffer.pop(0)
            self.block_number_uploaded_data += 1
            return struct.pack("!hh{}s".format(len(data)), self.TftpPacketType.DATA.value, self.block_number_uploaded_data, data)

        else:  # Creating the acknowledgement packet of the download operation
            return struct.pack("!hh", self.TftpPacketType.ACK.value, self.block_number_downloaded_data)
            return 0

        pass

    def reading_file(self, file_name):
        file = open(file_name, "rb")
        data = file.read()

        # Appending 512 byte chunks of data to the data buffer
        count = 0
        while count <= len(data):
            self.data_buffer.append(data[count: count + 512])
            count = count + 512

    def writing_file(self, file_name):
        file = open(file_name, "wb")
        for item in self.data_buffer:
            file.write(item)

    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def request_file(self, file_name):

        # Creating the read request packet
        rrq = '\0' + chr(self.TftpPacketType.RRQ.value) + file_name + '\0octet\0blksize\0512\0tsize\0' + '0' + '\0timeout\010\0'
        self.packet_buffer.append(struct.pack(str(len(rrq)) + 's', bytes(rrq, 'utf-8')))

    def upload_file(self, file_name):

        # Creating the write request packet
        wrq = '\0' + chr(self.TftpPacketType.WRQ.value) + file_name + '\0octet\0blksize\0512\0tsize\0' + '0' + '\0timeout\010\0'
        self.packet_buffer.append(struct.pack(str(len(wrq)) + 's', bytes(wrq, 'utf-8')))

    def has_pending_data_to_be_sent(self):
        return len(self.data_buffer) != 0


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)
    return client_socket, server_address


def do_socket_logic(opcode, client_socket, server_address, file_name):

    tftp_object = TftpProcessor()

    if opcode == 1:  # pull

        tftp_object.request_file(file_name)
        client_socket.sendto(tftp_object.get_next_output_packet(), server_address)
        data, server_packet = client_socket.recvfrom(516)
        tftp_object.process_udp_packet(data, server_packet)

        while tftp_object.has_pending_data_to_be_received:
            client_socket.sendto(tftp_object.get_next_output_packet(), server_packet)
            data, server_packet = client_socket.recvfrom(516)
            tftp_object.process_udp_packet(data, server_packet)

        tftp_object.writing_file(file_name)
        print('\n>> Data has been received')

    elif opcode == 2:  # push

        tftp_object.reading_file(file_name)
        tftp_object.upload_file(file_name)
        client_socket.sendto(tftp_object.get_next_output_packet(), server_address)

        while tftp_object.has_pending_data_to_be_sent():
            ack, server_packet = client_socket.recvfrom(1024)
            tftp_object.process_udp_packet(ack, server_packet)
            client_socket.sendto(tftp_object.get_next_output_packet(), server_packet)
        print('\n>> Data has been uploaded')
    else:
        print('>> Neither push nor pull request was found')
        pass
    pass


def parse_user_input(address, operation, file_name=None):
    client_socket, server_address = setup_sockets(address)
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        do_socket_logic(2, client_socket, server_address, file_name)  # for push .. parameter int of 02
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        do_socket_logic(1, client_socket, server_address, file_name)  # for push .. parameter int of 01
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
            exit(-1)  # Program execution failed.


def main():
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)
    ip_address = get_arg(1)
    operation = get_arg(2)
    file_name = get_arg(3)
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()