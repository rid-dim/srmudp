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
from typing import TYPE_CHECKING, Union, Deque, Tuple, Dict, Callable, Any, Sized, Optional
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
from .holepunch import HolePuncher
from .crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt
from .common import (
    Packet, packet2bin, bin2packet, CYC_INT0, CycInt,
    CONTROL_ACK, CONTROL_PSH, CONTROL_EOF, 
    CONTROL_RTM, CONTROL_FIN, MAX_RETRANSMIT_LIMIT, 
    MAX_TEMPORARY_PACKET_SIZE, SEND_BUFFER_SIZE,
    WINDOW_MAX_SIZE, SENDER_SOCKET_WAIT
)

# Make these available for backend.py
from .backend import ConnectionBackend

log = logging.getLogger(__name__)
# Define a struct for packet representation
# <BIBd means:
# B  - 1 byte for control flags
# I  - 4 bytes for sequence number (unsigned int) (so a ~6TB max file size? #TODO: check)
# B  - 4 bytes for retry count (unsigned int)
# d  - 8 bytes for timestamp (double)
packet_struct = Struct("<BIBd")

# Make FLAG_NAMES available for backend.py
FLAG_NAMES = {
    0b00000000: "---",
    CONTROL_ACK: "ACK",
    CONTROL_PSH: "PSH",
    CONTROL_EOF: "EOF",
    CONTROL_PSH | CONTROL_EOF: "PSH+EOF",
    CONTROL_RTM: "RTM",
    CONTROL_FIN: "FIN",
}

# typing
if TYPE_CHECKING:
    from Crypto.Cipher._mode_gcm import GcmMode
    from _typeshed import ReadableBuffer
    from typing import Sized
    _Address = Tuple[Any, ...]
    _WildAddress = Union[_Address, str, bytes]
    _MessageHook = Callable[['Packet', '_Address', 'SecureReliableSocket'], None]


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
        "message_hook_fnc", "loss", "try_connect", "established", "family", "message_buffer", 
        "my_public_key", "peer_public_key", "port", "backend", "backend_thread"
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

        # message hook
        # note: don't block this method or backend thread will be broken
        self.message_hook_fnc: Optional['_MessageHook'] = None

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
            # Verwende HolePuncher für den Verbindungsaufbau
            holepuncher = HolePuncher(family=self.receiver_socket.family, timeout=self._timeout, span=self.span)
            shared_key, peer_address, mtu, my_pk, peer_pk = holepuncher.establish_connection(self.receiver_socket, address, logger=log)
            self.shared_key = shared_key
            # Log the hashed shared_key for debugging (not the actual key for security reasons)
            log.debug('Shared key hash: %s', sha256(self.shared_key).hexdigest())
            self.address = peer_address
            self.mtu_size = mtu
            self.my_public_key = my_pk
            self.peer_public_key = peer_pk
            log.debug(f"connect success! mtu={self.mtu_size}")
            
            # Create and start backend thread
            self.backend = ConnectionBackend(
                socket=self.receiver_socket,
                zmq_push=self.zmq_push,
                shared_key=self.shared_key,
                address=self.address,
                span=self.span, 
                timeout=self._timeout,
                sender_buffer=self.sender_buffer,
                sender_buffer_lock=self.sender_buffer_lock,
                sender_signal=self.sender_signal,
                local_address=self.local_address,
                message_hook_fnc=self.message_hook_fnc,
                peer_public_key=self.peer_public_key
            )
            self.backend_thread = threading.Thread(target=self.backend.run, name="SRMUDP", daemon=True)
            self.backend_thread.start()
            
            self.established = True
            atexit.register(self.close)
            # Log connection establishment details
            log.debug('Connection established with peer: %s, MTU: %d', self.address, self.mtu_size)
        except Exception as e:
            log.error(f"Connection error: {e}")
            self.close()
            raise

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
        
        # Backend schließen, falls es existiert
        if hasattr(self, 'backend') and self.backend:
            self.backend.close()
            
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

    def _send_buffer_is_full(self) -> bool:
        """Check if the send buffer is full."""
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

    def sendall(self, data: 'ReadableBuffer', flags: int = 0) -> None:
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
                    
                # Update loss value from backend
                if hasattr(self, 'backend') and self.backend:
                    self.loss = self.backend.loss
                    
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
        return aes_gcm_encrypt(self.shared_key, data)

    def _decrypt(self, data: bytes) -> bytes:
        """decrypt by AES-GCM (more secure than CBC mode)"""
        return aes_gcm_decrypt(self.shared_key, data)

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

    def message_hook(packet: Packet, sender_address: '_Address', _sock: SecureReliableSocket) -> None:
        sender_str = f"{sender_address[0]}:{sender_address[1]}"
        log.debug("find you!!! from %s (%s)", sender_str, packet)

    sock.message_hook_fnc = message_hook
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
