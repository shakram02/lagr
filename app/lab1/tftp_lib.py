from enum import Enum
import struct


class TftpOpCodes(Enum):
    RRQ = b"\x00\x01"
    WRQ = b"\x00\x02"
    DATA = b"\x00\x03"
    ACK = b"\x00\x04"
    ERROR = b"\x00\x05"


class Packet(object):
    STRIDE_SIZE = 512

    def __init__(self, opcode: TftpOpCodes):
        self.opcode = opcode

    def __repr__(self):
        if self.opcode == TftpOpCodes.RRQ or self.opcode == TftpOpCodes.WRQ:
            return f"{self.opcode.name} FNAME: {self.fname} MODE: {self.mode}"
        elif self.opcode == TftpOpCodes.DATA:
            return f"DATA #{self.blk} LEN: [{len(self.data)}]"
        elif self.opcode == TftpOpCodes.ACK:
            return f"ACK #{self.blk}"
        elif self.opcode == TftpOpCodes.ERROR:
            return f"ERR ERRCODE: {self.err_code} MSG: {self.err_msg}"

    def __str__(self):
        return self.__repr__()

    @staticmethod
    def make_rrq(fname, mode="octet"):
        p = Packet(TftpOpCodes.RRQ)
        p.fname = fname
        p.mode = mode

        return p

    @staticmethod
    def make_wrq(fname, mode="octet"):
        p = Packet(TftpOpCodes.WRQ)
        p.fname = fname
        p.mode = mode

        return p

    @staticmethod
    def make_data(blk, data_bytes):
        p = Packet(TftpOpCodes.DATA)
        p.blk = blk
        p.data = data_bytes

        return p

    @staticmethod
    def make_ack(blk):
        p = Packet(TftpOpCodes.ACK)
        p.blk = blk

        return p

    @staticmethod
    def make_err(err_code, err_msg):
        p = Packet(TftpOpCodes.ERROR)
        p.err_code = err_code
        p.err_msg = err_msg

        return p

    @staticmethod
    def parse_packet_bytes(packet_bytes):
        opcode = TftpOpCodes(packet_bytes[:2])

        if opcode == TftpOpCodes.RRQ or opcode == TftpOpCodes.WRQ:
            return Packet.parse_rq_bytes(packet_bytes)
        elif opcode == TftpOpCodes.DATA:
            return Packet.parse_data_bytes(packet_bytes)
        elif opcode == TftpOpCodes.ACK:
            return Packet.parse_ack_bytes(packet_bytes)
        elif opcode == TftpOpCodes.ERROR:
            return Packet.parse_err_bytes(packet_bytes)

    @staticmethod
    def parse_rq_bytes(rq_bytes: bytes):
        p = Packet(TftpOpCodes(rq_bytes[:2]))

        rq_bytes = rq_bytes[2:]
        fname, mode = rq_bytes.split(b"\x00", 1)
        p.fname = str(fname).strip()
        p.mode = str(mode[:-1])

        return p

    @staticmethod
    def parse_data_bytes(data_bytes: bytes):
        p = Packet(TftpOpCodes(data_bytes[:2]))

        p.blk = struct.unpack("!H", data_bytes[2:4])[0]
        p.data = data_bytes[4:]
        p.last = len(p.data) < Packet.STRIDE_SIZE

        if len(p.data) > Packet.STRIDE_SIZE:
            raise ValueError("Invalid data size.")

        return p

    @staticmethod
    def parse_ack_bytes(ack_bytes: bytes):
        p = Packet(TftpOpCodes(ack_bytes[:2]))
        p.blk = struct.unpack("!H", ack_bytes[2:])[0]

        return p

    @staticmethod
    def parse_err_bytes(err_bytes: bytes):
        p = Packet(TftpOpCodes(err_bytes[:2]))

        p.err_code = err_bytes[2:4]
        p.err_msg = err_bytes[4:-1]

        return p

    @staticmethod
    def serialize_packet(packet) -> bytes:
        if packet.opcode == TftpOpCodes.RRQ or packet.opcode == TftpOpCodes.WRQ:
            return Packet.serialize_rq_packet(packet)
        elif packet.opcode == TftpOpCodes.DATA:
            return Packet.serialize_data_packet(packet)
        elif packet.opcode == TftpOpCodes.ACK:
            return Packet.serialize_ack_packet(packet)
        elif packet.opcode == TftpOpCodes.ERROR:
            return Packet.serialize_err_packet(packet)

    @staticmethod
    def serialize_rq_packet(packet) -> bytes:
        buffer = bytearray()

        buffer.extend(bytes(packet.opcode.value))
        buffer.extend(bytes(packet.fname, "UTF-8"))
        buffer.append(0)
        buffer.extend(bytes("octet", "UTF-8"))
        buffer.append(0)

        return bytes(buffer)

    @staticmethod
    def serialize_data_packet(packet) -> bytes:
        buffer = bytearray()
        buffer.extend(bytes(packet.opcode.value))
        buffer.extend(struct.pack("!H", packet.blk))
        buffer.extend(packet.data)

        return bytes(buffer)

    @staticmethod
    def serialize_ack_packet(packet) -> bytes:
        buffer = bytearray()
        buffer.extend(bytes(packet.opcode.value))
        buffer.extend(struct.pack("!H", packet.blk))

        return bytes(buffer)

    @staticmethod
    def serialize_err_packet(packet) -> bytes:
        buffer = bytearray()
        buffer.extend(bytes(packet.opcode.value))
        buffer.extend(struct.pack("!H", packet.err_code))
        buffer.extend(bytes(packet.err_msg, "UTF-8"))
        buffer.append(0)

        return bytes(buffer)
