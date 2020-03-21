import socket
import sys
import os
import enum
import struct


class TftpProcessor(object):

    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        self.packet_buffer = []
        pass


def _parse_udp_packet(data, packet_bytes):
    opcode = struct.unpack("!H", data[0:2])[0]
    if opcode == 4:
        return 1
    elif opcode == 5:
        errorpacket = data[4:]
        print(errorpacket.decode("UTF8"))
        return opcode
    else:
        return opcode

pass


def _do_some_logic(self, input_packet):
    s = readfile(get_arg(3, "test.txt"))
    return s

    pass


def request_file(address, file_name):
    print("Attempting to download ", file_name)
    sock, server_address = setup_sockets(address)
    opcode = 1
    zero = 0
    Mode = "octet"
    packet = struct.pack("!H8sB5sB", opcode, str.encode(file_name, 'ascii'), zero, str.encode(Mode, 'ascii'), zero)
    sock.sendto(packet, server_address)
    m = 0
    while (1):
        server_packet = sock.recvfrom(2048)
        data, sadderss = server_packet
        # print(len(data))
        flag = 0
        if len(data[4:]) == 0:
            if m == 0:
              print("TEXT file is empty")
            break
        if len(data[4:]) % 512 != 0:
            flag = 1
        pass
        blkno = int.from_bytes((data[2:4]), byteorder='big', signed=False)
        opcode2 = 4
        packet2 = struct.pack("!HH", opcode2, blkno)
        sock.sendto(packet2, sadderss)
        filetext = data.decode("UTF8")[4:]
        writefile(str(filetext))
        s = _parse_udp_packet(data, sadderss)
        if flag == 1:
            break
        m = m + 1
        pass

    pass


pass


def upload_file(address, file_name):
    sock, server_address = setup_sockets(address)
    opcode = 2
    zero = 0
    Mode = "octet"
    packet = struct.pack("!H8sB5sB", opcode, str.encode(file_name, 'ascii'), zero, str.encode(Mode, 'ascii'), zero)
    sock.sendto(packet, server_address)
    server_packet = sock.recvfrom(2048)
    data, sadderss = server_packet
    s = _parse_udp_packet(data, sadderss)
    if s == 1:
        file = readfile(file_name)
        opcode = 3
        for x in range(0, len(file)):
            if len(file[x]) < 512:
                y = len(file[x])
                packet2 = struct.pack("!HH" + str(y) + "s", opcode, x + 1, file[x])
                pass
            else:
                packet2 = struct.pack("!HH512s", opcode, x + 1, file[x])
                pass
            sock.sendto(packet2, sadderss)
            server_packet2 = sock.recvfrom(2048)
            ndata, nadderss = server_packet2
            p = _parse_udp_packet(ndata, nadderss)
            if p != 1:
                break
    pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print("[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", 69)
    # server_packet = client_socket.recvfrom(69)
    return client_socket, server_address
pass


def parse_user_input(address, operation, file_name):
    if operation == "push":
       upload_file(address,file_name)
       pass

    elif operation == "pull":
         request_file(address, file_name)
         pass
    else:
        print("Enter valid Operation !!")

pass


def readfile(file_name):
    f = open(file_name, "rb")
    s = []
    size = os.path.getsize(file_name)
    y = int(size / 512)
    for x in range(0, y + 1):
        s.append(f.read(512))
    return s


def writefile(data):
    f = open("test2.txt", "a")
    f.write(data)
    f.close()
pass


pass


def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print("[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")
    print(operation)
    print(ip_address)
    print(file_name)
    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
