"""
Common classes and utilities shared between srmudp modules.
"""
from typing import TYPE_CHECKING, NamedTuple, Optional, Tuple, Any, Sized
from struct import Struct
import logging

# Control flags
CONTROL_ACK = 0b00000001  # Acknowledge
CONTROL_PSH = 0b00000010  # Push data immediately
CONTROL_EOF = 0b00000100  # end of file
CONTROL_RTM = 0b00010000  # ask retransmission
CONTROL_FIN = 0b01000000  # fin

# Constants
WINDOW_MAX_SIZE = 32768  # 32kb
SEND_BUFFER_SIZE = WINDOW_MAX_SIZE * 8  # 256kb
MAX_RETRANSMIT_LIMIT = 4
MAX_TEMPORARY_PACKET_SIZE = 50000
SENDER_SOCKET_WAIT = 0.001  # sec

# Define a struct for packet representation
# <BIBd means:
# B  - 1 byte for control flags
# I  - 4 bytes for sequence number (unsigned int)
# B  - 4 bytes for retry count (unsigned int)
# d  - 8 bytes for timestamp (double)
packet_struct = Struct("<BIBd")

log = logging.getLogger(__name__)

class CycInt(int):
    """
    cycle 4bytes unsigned integer
    loop 0 ~ 0xffffffff
    """
    def __add__(self, other: int) -> 'CycInt':
        return CycInt(super().__add__(other) % 0x100000000)

    def __sub__(self, other: int) -> 'CycInt':
        return CycInt(super().__sub__(other) % 0x100000000)

    def __hash__(self) -> int:
        return self % 0x100000000

    def __lt__(self, other: int) -> bool:
        """self<value"""
        i = int(self)
        other = int(other)
        if i < 0x3fffffff:
            if other < 0xbfffffff:
                return i < other
            else:
                return False
        elif i < 0xbfffffff:
            return i < other
        else:
            if other < 0x3fffffff:
                return True
            else:
                return i < other

    def __le__(self, other: int) -> bool:
        """self<=value"""
        if self == other:
            return True
        return self.__lt__(other)

    def __ge__(self, other: int) -> bool:
        """self>=value"""
        return not self.__lt__(other)

    def __gt__(self, other: int) -> bool:
        """self>value"""
        return not self.__le__(other)


# static cycle int
CYC_INT0 = CycInt(0)


class Packet(NamedTuple):
    """
    static 14b
    [control 1b]-[sequence(ack) 4b]-[retry 1b]-[time 8b]-[data xb]
    """
    control: int  # control bit
    sequence: CycInt  # packet order (cycle 4bytes uint)
    retry: int  # re-transmission count (disconnected before overflow)
    time: float  # unix time (double)
    data: bytes  # data body
    sender_address: Optional[Tuple[str, int]] = None  # (ip, port) of sender

    def __repr__(self) -> str:
        addr_str = f", from={self.sender_address[0]}:{self.sender_address[1]}" if self.sender_address else ""
        flag_names = {
            0b00000000: "---",
            CONTROL_ACK: "ACK",
            CONTROL_PSH: "PSH",
            CONTROL_EOF: "EOF",
            CONTROL_PSH | CONTROL_EOF: "PSH+EOF",
            CONTROL_RTM: "RTM",
            CONTROL_FIN: "FIN",
        }
        return "Packet({} seq:{} retry:{} time:{} data:{}b{})".format(
            flag_names.get(self.control, hex(self.control)), self.sequence,
            self.retry, round(self.time, 2), len(self.data), addr_str)


def bin2packet(b: bytes, sender_address: Optional[Tuple[str, int]] = None) -> 'Packet':
    # Directly use the packet_struct from this module
    # control, sequence, retry, time
    c, seq, r, t = packet_struct.unpack_from(b)
    # Packet(control, sequence, retry, time, data)
    return Packet(c, CycInt(seq), r, t, b[packet_struct.size:], sender_address)


def packet2bin(p: Packet) -> bytes:
    # Directly use the packet_struct from this module
    # Packet => binary data
    return packet_struct.pack(p.control, int(p.sequence), p.retry, p.time) + p.data 