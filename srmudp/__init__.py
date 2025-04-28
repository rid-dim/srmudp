"""
`connection()` establishment process
====
```uml
                  ┌─┐                                            ┌─┐
                  │A│                                            │B│
                  └┬┘                                            └┬┘
                   │              udp-hole-punching               │
                   │────────────────────────────────────────────> │
                   │                                              │
                   │           udp-hole-punching (fail)           │
                   │ X<───────────────────────────────────────────│
                   │                                              │
                   │               send B's publicKey             │
                   │ <────────────────────────────────────────────│
                   │                                              │
                   │ send sharedKey (encrypted by sharedPoint)    │ ╔═══════════════╗
                   │───────────────────────────────────────────────>║ B established ║
                   │                                              │ ╚═══════════════╝
╔════════════════╗ │ send establish flag (encrypted by sharedKey) │
║ A established  ║<───────────────────────────────────────────────│
╚════════════════╝ │                                              │
                  ┌┴┐                                            ┌┴┐
                  │A│                                            │B│
                  └─┘                                            └─┘
```

note
----
* only one of two hole-punching is success in most case.
* when both hole-punching is success, use high priority side's sharedKey, but is rare case.
* when both hole-punching is fail, you can't use UDP-hole-punching method in your network.
* sharedPoint is calculated by multiply secretKey with publicKey.
* sharedKey is random 256bit bytes, don't use sharedPoint as sharedKey.
"""
from typing import TYPE_CHECKING, NamedTuple, Optional, Union, Deque, Tuple, Dict, Callable, Any, Sized
from select import select
from time import sleep, time
from collections import deque
from hashlib import sha256
from binascii import a2b_hex
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from struct import Struct
from socket import socket
import socket as s
import threading
import logging
import atexit
import os
import zmq


log = logging.getLogger(__name__)
# Define a struct for packet representation
# <BIBd means:
# B  - 1 byte for control flags
# I  - 4 bytes for sequence number (unsigned int) (so a ~6TB max file size? #TODO: check)
# B  - 4 bytes for retry count (unsigned int)
# d  - 8 bytes for timestamp (double)
packet_struct = Struct("<BIBd")

CONTROL_ACK = 0b00000001  # Acknowledge
CONTROL_PSH = 0b00000010  # Push data immediately
CONTROL_EOF = 0b00000100  # end of file
CONTROL_BCT = 0b00001000  # broadcast
CONTROL_RTM = 0b00010000  # ask retransmission
# CONTROL_MTU = 0b00100000  # fix MTU size
CONTROL_FIN = 0b01000000  # fin
FLAG_NAMES = {
    0b00000000: "---",
    CONTROL_ACK: "ACK",
    CONTROL_PSH: "PSH",
    CONTROL_EOF: "EOF",
    CONTROL_PSH | CONTROL_EOF: "PSH+EOF",
    CONTROL_BCT: "BCT",
    CONTROL_RTM: "RTM",
    # CONTROL_MTU: "MTU",
    CONTROL_FIN: "FIN",
}
WINDOW_MAX_SIZE = 32768  # 32kb
SEND_BUFFER_SIZE = WINDOW_MAX_SIZE * 8  # 256kb
MAX_RETRANSMIT_LIMIT = 4
MAX_TEMPORARY_PACKET_SIZE = 50000
SENDER_SOCKET_WAIT = 0.001  # sec

# Path MTU Discovery
IP_MTU = 14
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0
IP_PMTUDISC_DO = 2

# connection stage
S_HOLE_PUNCHING = b'\x00'
S_SEND_PUBLIC_KEY = b'\x01'
S_SEND_SHARED_KEY = b'\x02'
S_ESTABLISHED = b'\x03'

# typing
if TYPE_CHECKING:
    from Crypto.Cipher._mode_gcm import GcmMode
    from _typeshed import ReadableBuffer
    from typing import Sized
    _Address = Tuple[Any, ...]
    _WildAddress = Union[_Address, str, bytes]
    _BroadcastHook = Callable[['Packet', '_Address', 'SecureReliableSocket'], None]


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
        return "Packet({} seq:{} retry:{} time:{} data:{}b{})".format(
            FLAG_NAMES.get(self.control), self.sequence,
            self.retry, round(self.time, 2), len(self.data), addr_str)


def bin2packet(b: bytes, sender_address: Optional[Tuple[str, int]] = None) -> 'Packet':
    # control, sequence, retry, time
    c, seq, r, t = packet_struct.unpack_from(b)
    # Packet(control, sequence, retry, time, data)
    return Packet(c, CycInt(seq), r, t, b[packet_struct.size:], sender_address)


def packet2bin(p: Packet) -> bytes:
    # log.debug("s>> %s", p)
    # Packet => binary data
    return packet_struct.pack(p.control, int(p.sequence), p.retry, p.time) + p.data


def get_formal_address_format(address: '_WildAddress', family: int = s.AF_INET) -> '_Address':
    """tuple of ipv4/6 correct address format"""
    assert isinstance(address, tuple), "cannot recognize bytes or str format"

    # getaddrinfo() returns a list of tuples, each containing:
    # (family, socktype, proto, canonname, sa_addr)
    # sa_addr is a tuple (address, port)
    for _, _, _, _, addr in s.getaddrinfo(str(address[0]), int(address[1]), family, s.SOCK_STREAM):
        return addr
    else:
        raise ConnectionError("not found correct ip format of {}".format(address))


class SecureReliableSocket():
    __slots__ = [
        "_timeout", "span", "address", "local_address", "shared_key", "mtu_size",
        "sender_seq", "sender_buffer", "sender_signal", "sender_buffer_lock", "sender_time",
        "receiver_seq", "receiver_unread_size", "receiver_socket", "zmq_context", "zmq_push", "zmq_pull", "zmq_endpoint",
        "broadcast_hook_fnc", "loss", "try_connect", "established", "family", "message_buffer", 
        "my_public_key", "peer_public_key", "port"
    ]

    def __init__(self, port: int = 0, family: int = s.AF_INET, timeout: float = 21.0, span: float = 3.0) -> None:
        """
        :param port: Port to bind the socket to (0 = automatic port selection)
        :param family: socket type AF_INET or AF_INET6
        :param timeout: auto socket close by the time passed (sec)
        :param span: check socket status by the span (sec)
        """
    
        self.zmq_context = zmq.Context.instance()
        
        # Create a unique identifier for this socket instance
        socket_id = id(self)
        self.zmq_endpoint = f"inproc://srmudp-internal-{socket_id}"
        
        # Create PUSH/PULL sockets instead of PUB/SUB for better message handling
        self.zmq_push = self.zmq_context.socket(zmq.PUSH)
        # Wichtig: SNDHWM auf 0 setzen, damit keine Nachrichten verloren gehen
        self.zmq_push.setsockopt(zmq.SNDHWM, 0)
        self.zmq_push.bind(self.zmq_endpoint)
        
        self.zmq_pull = self.zmq_context.socket(zmq.PULL)
        # Wichtig: RCVHWM auf 0 setzen, damit keine Nachrichten verloren gehen
        self.zmq_pull.setsockopt(zmq.RCVHWM, 0) 
        self.zmq_pull.connect(self.zmq_endpoint)
        
        # Sofortiges Beenden beim Schließen aktivieren
        self.zmq_push.setsockopt(zmq.LINGER, 0)
        self.zmq_pull.setsockopt(zmq.LINGER, 0)
        
        # Weitere wichtige Socket-Optionen für bessere Integration mit asyncio
        # IPV6 aktivieren, falls unterstützt
        if hasattr(zmq, 'IPV6'):
            try:
                self.zmq_pull.setsockopt(zmq.IPV6, 1)
            except zmq.ZMQError:
                log.info("IPV6 not supported")
            
        log.debug(f"ZeroMQ PUSH/PULL sockets created for internal communication at {self.zmq_endpoint}")


        # inner params
        self._timeout = timeout
        self.span = span
        self.address: '_Address' = None
        self.local_address: '_Address' = None  # Lokale Bind-Adresse des Sockets
        self.shared_key: bytes = None
        self.mtu_size = 0  # 1472b
        self.sender_time = 0.0
        
        # Öffentliche Schlüssel für die Identifikation
        self.my_public_key: Optional[bytes] = None
        self.peer_public_key: Optional[bytes] = None

        # sender params
        self.sender_seq = CycInt(1)  # next send sequence
        self.sender_buffer: Deque[Packet] = deque() # deque is a double-ended queue that allows appending and popping from both ends efficiently.
        self.sender_signal = threading.Event()  # clear when buffer is empty
        self.sender_buffer_lock = threading.Lock()

        # receiver params
        self.receiver_seq = CycInt(1)  # next receive sequence
        self.receiver_unread_size = 0
        self.receiver_socket = socket(family, s.SOCK_DGRAM)
        
        # Binde den Socket an den angegebenen Port
        self.port = port
        self.receiver_socket.bind(("", port))
        self.local_address = self.receiver_socket.getsockname()
        log.debug(f"Socket bound to port {self.port} (actual: {self.local_address[1]})")
        
        # Buffer für die Zusammenstellung kompletter Nachrichten
        self.message_buffer = bytearray()

        # broadcast hook
        # note: don't block this method or backend thread will be broken
        self.broadcast_hook_fnc: Optional['_BroadcastHook'] = None

        # status
        self.loss = 0
        self.try_connect = False
        self.established = False

    def __repr__(self) -> str:
        if self.is_closed:
            status = "CLOSED"
        elif self.established:
            status = "ESTABLISHED"
        elif self.try_connect:
            status = "FAILED"
        else:
            status = "UNKNOWN"
        return "<SecureReliableSocket %s %s send=%s recv=%s loss=%s>"\
               % (status, self.get_socket_name(), self.sender_seq, self.receiver_seq, self.loss)

    def get_socket_name(self) -> str:
        """Return socket name in format 'IP:Port'"""
        if self.address is None:
            return "Not connected"
        return f"{self.address[0]}:{self.address[1]}"

    def connect(self, address: Union['_WildAddress', str]) -> None:
        """throw hole-punch msg, listen port and exchange keys"""
        assert not self.established, "already established"
        assert not self.is_closed, "already closed socket"
        assert not self.try_connect, "already try to connect"

        # Unterstützung für "IP:Port" Notation als String
        if isinstance(address, str) and ":" in address:
            host, port_str = address.rsplit(":", 1)
            address = (host, int(port_str))

        # start communication (only once you can try)
        self.try_connect = True

        try:
            # Formalisierte Adressformatierung
            conn_addr = get_formal_address_format(address)
            self.address = address = conn_addr
            log.debug(f"try to communicate addr={address} local={self.local_address}")

            # warning: allow only 256bit curve
            curve_name = 'P-256'
            log.debug("select curve {} (static)".format(curve_name))

            # 1. UDP hole punching
            punch_msg = b"udp hole punching"
            self.sendto(S_HOLE_PUNCHING + punch_msg + curve_name.encode(), address)

            # my secret & public key
            my_key = ECC.generate(curve=curve_name)
            my_pk_pem = my_key.public_key().export_key(format='PEM') # Export as PEM string
            my_pk_pem_bytes = my_pk_pem.encode('utf-8') # Encode PEM to bytes for sending
            
            # Speichere meinen öffentlichen Schlüssel
            self.my_public_key = my_pk_pem_bytes

            # other's public key
            other_pk: Optional[ECC.EccKey] = None

            check_msg = b"success hand shake"
            for _ in range(int(self._timeout / self.span)):
                r, _w, _x = select([self.receiver_socket.fileno()], [], [], self.span)
                if r:
                    data, _addr = self.receiver_socket.recvfrom(1024)
                    stage, data = data[:1], data[1:]

                    if stage == S_HOLE_PUNCHING:
                        # 2. send my public key
                        received_curve_name = data.replace(punch_msg, b'').decode()
                        assert curve_name == received_curve_name, ("different curve", curve_name, received_curve_name)
                        self.sendto(S_SEND_PUBLIC_KEY + my_pk_pem_bytes, address)
                        log.debug("success UDP hole punching")

                    elif stage == S_SEND_PUBLIC_KEY:
                        # 3. get public key & send shared key
                        other_pk = ECC.import_key(data) # Import directly from PEM bytes
                        # Speichere den öffentlichen Schlüssel des Partners
                        self.peer_public_key = data
                        shared_point = other_pk.pointQ * my_key.d # Calculate shared point (scalar multiplication)
                        coord_len = (shared_point.size_in_bits() + 7) // 8
                        temp_shared_key = SHA256.new(shared_point.x.to_bytes(coord_len, 'big') + shared_point.y.to_bytes(coord_len, 'big')).digest()
                        
                        # Generate a random session key and encrypt it with the derived shared key
                        session_key = os.urandom(32)
                        self.shared_key = temp_shared_key
                        encrypted_session_key = self._encrypt(session_key)
                        self.shared_key = session_key
                        
                        # Send own public key PEM bytes + encrypted session key hex
                        separator = b'|KEY|'
                        encrypted_data_payload = my_pk_pem_bytes + separator + encrypted_session_key.hex().encode('utf-8')
                        self.sendto(S_SEND_SHARED_KEY + encrypted_data_payload, address)
                        log.debug("success deriving ECDH key and sending encrypted session key")

                    elif stage == S_SEND_SHARED_KEY:
                        # 4. decrypt session key & send hello msg
                        separator = b'|KEY|'
                        parts = data.split(separator, 1)
                        if len(parts) != 2:
                            raise ConnectionError("Invalid S_SEND_SHARED_KEY format")
                        peer_pk_pem_bytes = parts[0]
                        encrypted_session_key_hex = parts[1].decode('utf-8')

                        if other_pk is None:
                            other_pk = ECC.import_key(peer_pk_pem_bytes) # Import directly from PEM bytes
                        else:
                            log.debug("need to check priority because already get others's pk")
                            my_pri = sha256(my_pk_pem_bytes + peer_pk_pem_bytes).digest()
                            other_pri = sha256(peer_pk_pem_bytes + my_pk_pem_bytes).digest()

                            if my_pri < other_pri:
                                log.debug("my priority is LOW and process received session key")
                            elif other_pri < my_pri:
                                log.debug("my priority is HIGH and ignore this command (use my session key)")
                                continue
                            else:
                                raise ConnectionError("my and other's key is same, this means you connect to yourself")
                        
                        if my_key is None:
                            raise ConnectionError("my_key not generated")
                        shared_point = other_pk.pointQ * my_key.d
                        coord_len = (shared_point.size_in_bits() + 7) // 8
                        derived_key = SHA256.new(shared_point.x.to_bytes(coord_len, 'big') + shared_point.y.to_bytes(coord_len, 'big')).digest()

                        self.shared_key = derived_key
                        decrypted_session_key = self._decrypt(a2b_hex(encrypted_session_key_hex))
                        self.shared_key = decrypted_session_key

                        self.sendto(S_ESTABLISHED + self._encrypt(check_msg), address)
                        log.debug("success decrypt session key")
                        break

                    elif stage == S_ESTABLISHED:
                        # 5. check establish by decrypt specific message
                        decrypt_msg = self._decrypt(data)
                        if decrypt_msg != check_msg:
                            raise ConnectionError("failed to check establish message")
                        log.debug("successful handshake")
                        break

                    else:
                        raise ConnectionError("not defined message received {}len".format(len(data)))
            else:
                # cannot establish
                raise ConnectionError("timeout on handshake")

            # get best MUT size
            # set don't-fragment flag & reset after
            # avoid Path MTU Discovery Blackhole
            self.receiver_socket.setsockopt(s.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
            self.mtu_size = self._find_mtu_size()
            self.receiver_socket.setsockopt(s.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
            log.debug("success get MUT size %db", self.mtu_size)

            # success establish connection
            threading.Thread(target=self._backend, name="SRMUDP", daemon=True).start()
            self.established = True

            # auto exit when program closed
            atexit.register(self.close)
            
        except Exception as e:
            log.error(f"Connection error: {e}")
            # Sicherstellen, dass wir die Ressourcen freigeben, wenn etwas schief geht
            self.close()
            # Re-raise die Exception, damit der Aufrufer weiß, was passiert ist
            raise

    def _find_mtu_size(self) -> int:
        """confirm by submit real packet"""
        wait = 0.05
        mut = 1472  # max ipv4:1472b, ipv6:1452b
        receive_size = 0
        my_mut_size = None
        finished_notify = False
        for _ in range(int(self._timeout / wait)):
            r, _w, _x = select([self.receiver_socket.fileno()], [], [], wait)
            if r:
                data, _addr = self.receiver_socket.recvfrom(1500)
                if data.startswith(b'#####'):
                    if len(data) < receive_size:
                        self.sendto(receive_size.to_bytes(4, 'little'), self.address)
                        finished_notify = True
                    else:
                        receive_size = max(len(data), receive_size)
                elif len(data) == 4:
                    my_mut_size = int.from_bytes(data, 'little')
                else:
                    pass
            elif finished_notify and my_mut_size:
                return my_mut_size
            elif 1024 < mut:
                try:
                    if my_mut_size is None:
                        self.sendto(b'#' * mut, self.address)
                except s.error:
                    pass
                mut -= 16
            else:
                pass
        else:
            raise ConnectionError("timeout on finding MUT size")

    def _backend(self) -> None:
        """reorder sequence & fill output buffer"""
        temporary: 'Dict[CycInt, Packet]' = dict()
        retransmit_packets: Deque[Packet] = deque()
        retransmitted: Deque[float] = deque(maxlen=16)
        last_packet: Optional[Packet] = None
        last_receive_time = time()
        last_ack_time = time()
        message_buffer = bytearray()  # Buffer für aktuelle Nachricht
        
        # Debug: Lokale Bind-Adresse
        if hasattr(self, 'local_address') and self.local_address is not None:
            log.debug(f"Backend thread started, local socket bound to {self.local_address[0]}:{self.local_address[1]}")
        else:
            self.local_address = self.receiver_socket.getsockname()
            log.debug(f"Backend thread started, local socket bound to {self.local_address[0]}:{self.local_address[1]}")
        
        log.debug(f"Peer address is {self.address[0]}:{self.address[1]}")
        
        while not self.is_closed:
            r, _w, _x = select([self.receiver_socket.fileno()], [], [], self.span)

            # re-transmit
            if 0 < len(self.sender_buffer):
                with self.sender_buffer_lock:
                    now = time() - self.span * 2
                    transmit_limit = MAX_RETRANSMIT_LIMIT  # max transmit at once
                    for i, p in enumerate(self.sender_buffer):
                        if transmit_limit == 0:
                            break
                        if p.time < now:
                            self.loss += 1
                            re_packet = Packet(p.control, p.sequence, p.retry+1, time(), p.data)
                            self.sender_buffer[i] = re_packet
                            self.sendto(self._encrypt(packet2bin(re_packet)), self.address)
                            transmit_limit -= 1

            # send ack as ping (stream may be free)
            if self.span < (time() - last_ack_time):
                p = Packet(CONTROL_ACK, self.receiver_seq - 1, 0, time(), b'as ping')
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                last_ack_time = time()

            # connection may be broken - send FIN just to notify that i'm closing
            if self._timeout < time() - last_receive_time:
                p = Packet(CONTROL_FIN, CYC_INT0, 0, time(), b'stream may be broken')
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                break

            # if no data received, continue
            if len(r) == 0:
                continue

            """received a packet data"""

            try:
                if self.receiver_seq in temporary:
                    packet = temporary.pop(self.receiver_seq)
                else:
                    # Der eigentliche Empfang des Pakets - hier sehen wir die tatsächliche Absenderadresse!
                    data, addr = self.receiver_socket.recvfrom(65536)
                    # Decrypt und erstelle das Packet mit der Absenderadresse, die wir gerade gesehen haben 
                    packet = bin2packet(self._decrypt(data), addr)
                    # Debug-Ausgabe für Absenderadresse
                    log.debug(f"Received packet from {addr[0]}:{addr[1]} (expected peer: {self.address[0]}:{self.address[1]})")

                last_receive_time = time()
                # log.debug("r<< %s", packet)
            except ValueError:
                # log.debug("decrypt failed len=%s..".format(data[:10]))
                continue
            except (ConnectionResetError, OSError):
                break
            except Exception:
                log.error("UDP socket closed", exc_info=True)
                break

            # receive ack
            if packet.control & CONTROL_ACK: # masking for ACK bit
                with self.sender_buffer_lock:
                    if 0 < len(self.sender_buffer):
                        for seq in range(self.sender_buffer[0].sequence, packet.sequence + 1):
                            # remove packet that sent and confirmed by ACK
                            self.sender_buffer.popleft()
                            if len(self.sender_buffer) == 0:
                                break
                        if not self._send_buffer_is_full():
                            self.sender_signal.set()
                            log.debug("allow sending operation again seq={}".format(packet.sequence))
                continue

            # receive reset
            if packet.control & CONTROL_FIN:
                p = Packet(CONTROL_FIN, CYC_INT0, 0, time(), b'been notified fin or reset')
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                break

            # asked re-transmission
            if packet.control & CONTROL_RTM: # masking for RTM bit
                with self.sender_buffer_lock:
                    for i, p in enumerate(self.sender_buffer):
                        if p.sequence == packet.sequence:
                            # Füge meinen Public Key zum Paket hinzu, um eine eindeutige Identifikation für die Retransmission zu ermöglichen
                            re_data = p.data
                            re_packet = Packet(p.control, p.sequence, p.retry+1, time(), re_data)
                            self.sender_buffer[i] = re_packet
                            self.sendto(self._encrypt(packet2bin(re_packet)), self.address)
                            retransmitted.append(packet.time)
                            break  # success
                    else:
                        log.error("cannot find packet to retransmit seq={}".format(packet.sequence))
                        break
                continue

            # broadcast packet
            if packet.control & CONTROL_BCT:
                # Benutze das broadcast_hook_fnc, wenn es konfiguriert ist
                if self.broadcast_hook_fnc is not None:
                    self.broadcast_hook_fnc(packet, packet.sender_address or self.address, self)
                # Ansonsten sende das Paket direkt an die ZeroMQ-Queue
                elif last_packet is None or last_packet.control & CONTROL_EOF:
                    # Broadcast-Nachrichten als eine vollständige Nachricht senden
                    # Füge den Public Key des Peers hinzu, wenn vorhanden
                    peer_key = None
                    if hasattr(packet, 'sender_key') and packet.sender_key:
                        peer_key = packet.sender_key
                    self._send_complete_message(packet.data, packet.sender_address, peer_key)
                else:
                    # note: acquire realtime response
                    log.debug("throw away %s", packet)
                continue

            """normal packet from here (except PSH, EOF)"""

            # check the packet is retransmitted
            if 0 < packet.retry and 0 < len(retransmit_packets):
                limit = time() - self.span
                for i, p in enumerate(retransmit_packets):
                    if p.sequence == packet.sequence:
                        del retransmit_packets[i]
                        break  # success retransmitted
                    if p.sequence < self.receiver_seq:
                        del retransmit_packets[i]
                        break  # already received
                for i, p in enumerate(retransmit_packets):
                    # too old retransmission request
                    if p.time < limit:
                        re_packet = Packet(CONTROL_RTM, p.sequence, p.retry+1, time(), b'')
                        retransmit_packets[i] = re_packet
                        self.sendto(self._encrypt(packet2bin(re_packet)), self.address)
                        self.loss += 1
                        break

            # receive data
            if packet.sequence == self.receiver_seq:
                self.receiver_seq += 1
                
                # Zu Message-Buffer hinzufügen
                message_buffer.extend(packet.data)
                
                # Wenn EOF oder PSH, senden wir die komplette Nachricht über ZeroMQ
                if packet.control & CONTROL_EOF:
                    self._send_complete_message(bytes(message_buffer), packet.sender_address)
                    message_buffer.clear()
            elif packet.sequence > self.receiver_seq:
                temporary[packet.sequence] = packet
                # ask re-transmission if not found before packet
                if MAX_TEMPORARY_PACKET_SIZE < len(temporary):
                    log.error("too many temporary packets stored")
                    break

                # check self.receiver_seq to packet.sequence for each
                for lost_seq in map(CycInt, range(packet.sequence - 1, self.receiver_seq - 1, -1)):
                    if lost_seq in temporary:
                        continue  # already received packet
                    for p in retransmit_packets:
                        if p.sequence == lost_seq:
                            break  # already pushed request
                    else:
                        re_packet = Packet(CONTROL_RTM, lost_seq, 0, time(), b'')
                        self.sendto(self._encrypt(packet2bin(re_packet)), self.address)
                        self.loss += 1
                        retransmit_packets.append(re_packet)
                        log.debug("ask retransmit seq={}".format(lost_seq))

                # clean temporary
                if min(temporary.keys()) < self.receiver_seq:
                    for seq in tuple(temporary.keys()):
                        if seq < self.receiver_seq:
                            del temporary[seq]

                log.debug("continue listen socket and reorder packet")
                continue
            else:
                continue  # ignore old packet

            # push buffer immediately
            if packet.control & CONTROL_PSH:
                # send ack
                p = Packet(CONTROL_ACK, self.receiver_seq - 1, 0, time(), b'put buffer')
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                last_ack_time = time()
                # log.debug("pushed! buffer %d %s", len(retransmit_packets), retransmit_packets)

            # reached EOF & push broadcast packets
            if packet.control & CONTROL_EOF:
                # note: stopped sending broadcast packet after main stream for realtime
                log.debug("reached end of chunk seq={}".format(packet.sequence))

            # update last packet
            last_packet = packet
            
            # Save reference to last packet in current thread for EOF detection in _push_receive_buffer
            threading.current_thread()._last_packet = packet

        # close
        log.debug("srmudp socket is closing now")
        self.close()

    def _send_complete_message(self, data: bytes, sender_address: '_Address' = None, sender_key: bytes = None) -> None:
        """Sendet eine vollständige Nachricht an den ZeroMQ-Kanal"""
        log.debug(f"Sending complete message: {len(data)} bytes")
        self.receiver_unread_size += len(data)
        
        try:
            # Wenn kein Absender angegeben ist, verwende die Peer-Adresse
            if sender_address is None:
                sender_address = self.address
            
            sender_key = sender_key or self.peer_public_key
            
            # Für Debug-Zwecke
            if sender_address == self.address:
                log.debug(f"Using peer address as sender: {sender_address}")
            else:
                log.debug(f"Using specific sender address: {sender_address}")
            
            # Format für den Sender: "IP:Port"
            # Wichtig: Bei einem Tuple (IP, Port) ist das das Format, das wir brauchen
            if isinstance(sender_address, tuple) and len(sender_address) >= 2:
                sender_str = f"{sender_address[0]}:{sender_address[1]}"
            else:
                # Fallback, falls wir ein anderes Format bekommen
                sender_str = str(sender_address)
            
            # Prepare the message: sender (string) + public key + data as multipart message
            # Send through ZeroMQ
            parts = [sender_str.encode('utf-8')]
            
            # Wenn wir einen Public Key haben, fügen wir ihn hinzu
            if sender_key is not None:
                parts.append(sender_key)
            else:
                # Leerer Platzhalter für konsistente Nachrichtenformate
                parts.append(b'')
            
            # Daten anhängen
            parts.append(data)
            
            # Senden der Nachricht mit allen Teilen
            self.zmq_push.send_multipart(parts)
            log.debug(f"Successfully sent complete message of {len(data)} bytes from {sender_str} to ZeroMQ buffer")
        except OSError as e:
            log.error(f"OSError writing to ZeroMQ socket: {e}")
        except Exception as e:
            log.error(f"Error writing to ZeroMQ socket: {e}")

    def _send_buffer_is_full(self) -> bool:
        assert self.sender_buffer_lock.locked(), 'unlocked send_buffer!'
        return SEND_BUFFER_SIZE < sum(len(p.data) for p in self.sender_buffer)

    def get_window_size(self) -> int:
        """maximum size of data you can send at once"""
        # Packet = [nonce 16b][tag 16b][static 14b][data xb]
        return self.mtu_size - 32 - packet_struct.size

    def send(self, data: 'ReadableBuffer', flags: int = 0) -> int:
        """over write low-level method for compatibility"""
        assert flags == 0, "unrecognized flags"
        assert isinstance(data, Sized)
        self.sendall(data)
        return len(data)

    def _send(self, data: memoryview) -> int:
        """warning: row-level method"""
        if not self.established:
            raise ConnectionAbortedError('disconnected')

        window_size = self.get_window_size()
        length = len(data) // window_size
        send_size = 0
        for i in range(length + 1):
            # control flag
            control = 0b00000000
            with self.sender_buffer_lock:
                buffer_is_full = self._send_buffer_is_full()
            if i == length or buffer_is_full:
                control |= CONTROL_PSH
            if i == length:
                control |= CONTROL_EOF

            # note: sleep at least SOCKET_WAIT mSec to avoid packet loss
            space_time = SENDER_SOCKET_WAIT - time() + self.sender_time
            if 0.0 < space_time:
                sleep(space_time)

            # send one packet
            throw = data[window_size * i:window_size * (i + 1)]
            with self.sender_buffer_lock:
                # Bei der Packet-Erstellung verwenden wir KEINE Absenderadresse
                # Der Empfänger setzt diese beim Empfang basierend auf seiner Sicht
                packet = Packet(control, self.sender_seq, 0, time(), throw.tobytes())
                self.sender_buffer.append(packet)
                self.sendto(self._encrypt(packet2bin(packet)), self.address)
                self.sender_seq += 1
            self.sender_time = time()
            send_size += len(throw)

            # block sendall() when buffer is full
            if buffer_is_full:
                self.sender_signal.clear()
                log.debug("buffer is full and wait for signaled")
                break
        return send_size

    def sendto(self, data: 'ReadableBuffer', address: '_Address') -> int:  # type: ignore
        """row-level method: guarded by `sender_buffer_lock`, don't use.."""
        if self.is_closed:
            return 0
        # Verwende immer das gleiche Socket zum Senden
        return self.receiver_socket.sendto(data, address)

    def send(self, data: 'ReadableBuffer', flags: int = 0) -> None:
        """high-level method, use this instead of send()"""
        assert flags == 0, "unrecognized flags"
        send_size = 0
        data = memoryview(data)
        while send_size < len(data):
            with self.sender_buffer_lock:
                if not self._send_buffer_is_full():
                    self.sender_signal.set()
            if self.sender_signal.wait(self._timeout):
                send_size += self._send(data[send_size:])
            elif not self.established:
                raise ConnectionAbortedError('disconnected')
            else:
                log.debug("waiting for sending buffer have space..")
        log.debug("send operation success %sb", send_size)

    def broadcast(self, data: bytes) -> None:
        """broadcast data (do not check reach)"""
        if not self.established:
            raise ConnectionAbortedError('disconnected')
        # do not check size
        # window_size = self.get_window_size()
        # if window_size < len(data):
        #    raise ValueError("data is too big {}<{}".format(window_size, len(data)))
        # Keine Absenderadresse setzen - der Empfänger bestimmt diese
        packet = Packet(CONTROL_BCT | CONTROL_EOF, CYC_INT0, 0, time(), data)
        with self.sender_buffer_lock:
            self.sendto(self._encrypt(packet2bin(packet)), self.address)

    def receive(self, flags: int = 0, timeout: float = 1.0) -> Optional[Tuple[str, bytes, Optional[bytes]]]:
        """
        Wait for and return a complete message with sender information.
        
        This function waits until a complete message is available or until the 
        timeout expires. If a complete message is available, it returns a tuple with
        the sender address ("IP:Port"), message bytes, and optionally the sender's public key. 
        If the timeout expires, it returns None.
        
        Args:
            flags: Must be 0 (reserved for future use)
            timeout: Maximum time to wait for a complete message in seconds
            
        Returns:
            A tuple (sender, message, public_key) where sender is a string in the format "IP:Port",
            message is bytes, and public_key is the sender's public key or None. Returns None if timeout occurred.
        """
        assert flags == 0, "unrecognized flags"
        self.sender_time = time()  # update last accessed time

        if self.is_closed or not self.established:
            return None

        log.debug(f"receive: starting with timeout={timeout}s")

        try:
            poller = zmq.Poller()
            poller.register(self.zmq_pull, zmq.POLLIN)

            # Wait for incoming message with timeout
            if poller.poll(timeout * 1000):  # timeout in milliseconds
                # Receive multipart message [sender_addr, sender_key, data]
                parts = self.zmq_pull.recv_multipart()
                
                if len(parts) < 2:
                    log.warning(f"receive: Got {len(parts)} message parts instead of expected 3")
                    return None
                    
                sender_bytes = parts[0]
                sender = sender_bytes.decode('utf-8')
                
                # Wenn wir drei Teile haben, ist der zweite Teil der Public Key
                sender_key = None
                if len(parts) >= 3:
                    sender_key_bytes = parts[1]
                    # Wenn der Key nicht leer ist, verwende ihn
                    if sender_key_bytes:
                        sender_key = sender_key_bytes
                    data = parts[2]
                else:
                    # Älteres Format ohne Key
                    data = parts[1]
                
                # Debug: Wer war der Absender
                log.debug(f"receive: got complete message from {sender}, size={len(data)}b")
                log.debug(f"My local socket is bound to {self.receiver_socket.getsockname()}")
                
                # Empty data?
                if not data:
                    return sender, b'', sender_key
                    
                return sender, data, sender_key
            else:
                # Timeout occurred
                log.debug(f"receive: timeout ({timeout}s) with no complete message available")
                return None

        except zmq.ZMQError as e:
            log.error(f"ZMQ error in receive: {e}")
            return None
        except Exception as e:
            # Catch potential errors during processing
            log.error(f"Error processing message in receive: {e}", exc_info=True)
            return None

    def _encrypt(self, data: bytes) -> bytes:
        """encrypt by AES-GCM (more secure than CBC mode)"""
        cipher: 'GcmMode' = AES.new(self.shared_key, AES.MODE_GCM)
        # warning: Don't reuse nonce
        enc, tag = cipher.encrypt_and_digest(data)
        # output length = 16bytes + 16bytes + N(=data)bytes
        return bytes(cipher.nonce) + tag + enc

    def _decrypt(self, data: bytes) -> bytes:
        """decrypt by AES-GCM (more secure than CBC mode)"""
        cipher: 'GcmMode' = AES.new(self.shared_key, AES.MODE_GCM, nonce=data[:16])
        # ValueError raised when verify failed
        return cipher.decrypt_and_verify(data[32:], data[16:32])

    def getsockname(self) -> str:
        """self bind info or raise OSError"""
        if self.is_closed:
            raise OSError("socket is closed")
        else:
            sock_addr = self.receiver_socket.getsockname()
            return f"{sock_addr[0]}:{sock_addr[1]}"

    def getpeername(self) -> str:
        """connection info or raise OSError"""
        if self.is_closed:
            raise OSError("socket is closed")
        elif self.address is None:
            raise OSError("not found peer connection")
        else:
            return f"{self.address[0]}:{self.address[1]}"

    @property
    def is_closed(self) -> bool:
        if self.receiver_socket.fileno() == -1:
            self.established = False
            atexit.unregister(self.close)
            return True
        return False

    def close(self) -> None:
        # Wenn die Verbindung bereits geschlossen ist, nichts tun
        if self.is_closed:
            return
            
        # Nur ein FIN-Paket senden, wenn wir schon verbunden waren
        if self.established:
            self.established = False
            p = Packet(CONTROL_FIN, CYC_INT0, 0, time(), b'closed')
            try:
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                # just to give the FIN packet time to be sent and to end everything gracefully
                sleep(0.01)
            except:
                # Fehler beim Senden des FIN-Pakets ignorieren
                pass
        
        # try_connect zurücksetzen
        self.try_connect = False
            
        # ZeroMQ-Sockets sicher schließen
        try:
            log.debug(f"Closing ZeroMQ sockets for {self.zmq_endpoint}")
            if hasattr(self, 'zmq_pull') and self.zmq_pull:
                self.zmq_pull.close(linger=0)
            if hasattr(self, 'zmq_push') and self.zmq_push:
                self.zmq_push.close(linger=0)
            log.debug(f"ZeroMQ sockets closed for {self.zmq_endpoint}")
        except Exception as e:
            log.error(f"Error closing ZeroMQ sockets: {e}")
        
        # UDP-Socket schließen
        try:
            if hasattr(self, 'receiver_socket') and self.receiver_socket and self.receiver_socket.fileno() != -1:
                self.receiver_socket.close()
                log.debug("UDP receiver socket closed")
        except Exception as e:
            log.error(f"Error closing UDP receiver socket: {e}")
        
        # Established-Status zurücksetzen
        self.established = False
            
        # Aus dem at-exit Handler entfernen
        try:
            atexit.unregister(self.close)
        except Exception:
            pass


def get_mtu_linux(family: int, host: str) -> int:
    """MTU on Linux"""
    with socket(family, s.SOCK_DGRAM) as sock:
        sock.connect((host, 0))
        if family == s.AF_INET:
            # set option DF (only for ipv4)
            sock.setsockopt(s.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        return sock.getsockopt(s.IPPROTO_IP, IP_MTU)


def main() -> None:
    """for test"""
    import sys
    import random

    remote_host = sys.argv[1]
    port = int(sys.argv[2])
    msglen = int(sys.argv[3])

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '[%(levelname)-6s] [%(threadName)-10s] [%(asctime)-24s] %(message)s')
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    sock = SecureReliableSocket(port)
    sock.connect((remote_host, port))
    log.debug("connect success! mtu=%d", sock.mtu_size)

    def listen() -> None:
        size, start = 0, time()
        while True:
            r = sock.receive(timeout=1.0)
            if r is None:
                continue
            sender, data, key = r
            if len(data) == 0:
                break
            if 0 <= data.find(b'start!'):
                size, start = 0, time()
            size += len(data)
            if 0 <= data.find(b'success!'):
                span = max(0.000001, time()-start)
                log.debug("received! %db from %s, loss=%d %skb/s\n", 
                         size, sender, sock.loss, round(size/span/1000, 2))
            # log.debug("recv %d %d", size, len(r))
        log.debug("closed receive")

    def sending() -> None:
        while msglen:
            sock.send(b'start!'+os.urandom(msglen)+b'success!')  # +14
            log.debug("send now! loss=%d time=%d", sock.loss, int(time()))
            if 0 == random.randint(0, 5):
                sock.broadcast(b'find me! ' + str(time()).encode())
                log.debug("send broadcast!")
            sleep(20)

    def broadcast_hook(packet: Packet, sender_address: '_Address', _sock: SecureReliableSocket) -> None:
        sender_str = f"{sender_address[0]}:{sender_address[1]}"
        log.debug("find you!!! from %s (%s)", sender_str, packet)

    sock.broadcast_hook_fnc = broadcast_hook
    threading.Thread(target=listen).start()
    threading.Thread(target=sending).start()


if __name__ == '__main__':
    main()


__all__ = [
    "Packet",
    "bin2packet",
    "packet2bin",
    "get_formal_address_format",
    "SecureReliableSocket",
    "get_mtu_linux",
]
