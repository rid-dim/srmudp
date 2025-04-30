"""
Backend thread implementation for SecureReliableSocket.
Handles packet receiving, processing, and reordering.
"""
from typing import Dict, Deque, Optional, Tuple, Any, Callable
from select import select
from time import time, sleep
from collections import deque
import threading
import logging
import socket as s
import zmq

from .common import (
    Packet, packet2bin, bin2packet, CYC_INT0, CycInt,
    CONTROL_ACK, CONTROL_PSH, CONTROL_EOF, 
    CONTROL_RTM, CONTROL_FIN, MAX_RETRANSMIT_LIMIT, 
    MAX_TEMPORARY_PACKET_SIZE, SEND_BUFFER_SIZE
)
from .crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt

log = logging.getLogger(__name__)

class ConnectionBackend:
    """
    Backend thread implementation for SecureReliableSocket.
    Handles packet receiving, processing, and message reordering.
    """
    
    def __init__(
        self, 
        socket: s.socket,
        zmq_push: zmq.Socket,
        shared_key: bytes,
        address: Tuple[str, int],
        span: float, 
        timeout: float,
        sender_buffer: Deque[Packet],
        sender_buffer_lock: threading.Lock,
        sender_signal: threading.Event,
        local_address: Optional[Tuple[str, int]] = None,
        message_hook_fnc: Optional[Callable] = None,
        peer_public_key: Optional[bytes] = None
    ) -> None:
        """
        Initialize the ConnectionBackend.
        
        Args:
            socket: UDP socket for sending/receiving packets
            zmq_push: ZeroMQ socket for sending complete messages
            shared_key: Encryption key
            address: Peer address (ip, port)
            span: Time span for packet processing
            timeout: Connection timeout
            sender_buffer: Buffer for outgoing packets
            sender_buffer_lock: Lock for the sender buffer
            sender_signal: Event for signaling sender buffer state
            local_address: Local socket address
            message_hook_fnc: Function to handle incoming messages
            peer_public_key: Public key of the peer
        """
        self.socket = socket
        self.zmq_push = zmq_push
        self.shared_key = shared_key
        self.address = address
        self.span = span
        self.timeout = timeout
        self.sender_buffer = sender_buffer
        self.sender_buffer_lock = sender_buffer_lock
        self.sender_signal = sender_signal
        self.local_address = local_address or socket.getsockname()
        self.message_hook_fnc = message_hook_fnc
        self.peer_public_key = peer_public_key
        
        # Status and counters
        self.is_closed = False
        self.loss = 0
        self.receiver_seq = CycInt(1)  # next receive sequence
        self.receiver_unread_size = 0
        
    def run(self) -> None:
        """Main loop of the backend thread."""
        temporary: Dict[CycInt, Packet] = dict()
        retransmit_packets: Deque[Packet] = deque()
        retransmitted: Deque[float] = deque(maxlen=16)
        last_packet: Optional[Packet] = None
        last_receive_time = time()
        last_ack_time = time()
        message_buffer = bytearray()  # Buffer for current message
        
        # Debug: Local bind address
        log.debug(f"Backend thread started, local socket bound to {self.local_address[0]}:{self.local_address[1]}")
        log.debug(f"Peer address is {self.address[0]}:{self.address[1]}")
        
        while not self.is_closed:
            r, _w, _x = select([self.socket.fileno()], [], [], self.span)

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
            if self.timeout < time() - last_receive_time:
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
                    # Actual packet reception - here we see the real sender address!
                    data, addr = self.socket.recvfrom(65536)
                    # Decrypt and create the packet with the sender address we just saw
                    packet = bin2packet(self._decrypt(data), addr)
                    # Debug output for sender address
                    #log.debug(f"Received packet from {addr[0]}:{addr[1]} (expected peer: {self.address[0]}:{self.address[1]})")

                last_receive_time = time()
                # Log if ACK is received
                #log.debug('Received ACK for sequence %s', packet.sequence)
            except ValueError:
                # Log decryption errors
                log.debug('Decryption failed for packet data: %s', data[:10])
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

            # note: no ack for FIN packet
            if packet.control & CONTROL_FIN:
                p = Packet(CONTROL_FIN, CYC_INT0, 0, time(), b'been notified fin or reset')
                self.sendto(self._encrypt(packet2bin(p)), self.address)
                break

            # asked re-transmission
            if packet.control & CONTROL_RTM: # masking for RTM bit
                with self.sender_buffer_lock:
                    for i, p in enumerate(self.sender_buffer):
                        if p.sequence == packet.sequence:
                            # Add sender identification for retransmission
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
                
                # Add to message buffer
                message_buffer.extend(packet.data)
                
                # If EOF or PSH, send the complete message via ZeroMQ
                if packet.control & CONTROL_EOF:
                    # If message_hook_fnc is set, use it for handling the message
                    if self.message_hook_fnc is not None:
                        self.message_hook_fnc(packet, packet.sender_address or self.address, self)
                    # Otherwise send the message directly to the ZeroMQ queue
                    else:
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

            # reached EOF
            if packet.control & CONTROL_EOF:
                log.debug("reached end of chunk seq={}".format(packet.sequence))

            # update last packet
            last_packet = packet
            
            # Save reference to last packet in current thread for EOF detection
            threading.current_thread()._last_packet = packet

        # close
        log.debug("Backend thread closing")
        self.is_closed = True

    def _send_buffer_is_full(self) -> bool:
        """Check if the send buffer is full."""
        assert self.sender_buffer_lock.locked(), 'unlocked send_buffer!'
        return SEND_BUFFER_SIZE < sum(len(p.data) for p in self.sender_buffer)

    def _send_complete_message(self, data: bytes, sender_address: Optional[Tuple[str, int]] = None, sender_key: Optional[bytes] = None) -> None:
        """Send a complete message to the ZeroMQ channel."""
        log.debug(f"Sending complete message: {len(data)} bytes")
        self.receiver_unread_size += len(data)
        
        try:
            # If no sender is specified, use the peer address
            if sender_address is None:
                sender_address = self.address
            
            sender_key = sender_key or self.peer_public_key
            
            # For debug purposes
            if sender_address == self.address:
                log.debug(f"Using peer address as sender: {sender_address}")
            else:
                log.debug(f"Using specific sender address: {sender_address}")
            
            # Format for the sender: "IP:Port"
            # Important: For a tuple (IP, Port) this is the format we need
            if isinstance(sender_address, tuple) and len(sender_address) >= 2:
                sender_str = f"{sender_address[0]}:{sender_address[1]}"
            else:
                # Fallback if we get another format
                sender_str = str(sender_address)
            
            # Prepare the message: sender (string) + public key + data as multipart message
            # Send through ZeroMQ
            parts = [sender_str.encode('utf-8')]
            
            # If we have a public key, add it
            if sender_key is not None:
                parts.append(sender_key)
            else:
                # Empty placeholder for consistent message formats
                parts.append(b'')
            
            # Append data
            parts.append(data)
            
            # Log ZeroMQ message sending
            log.debug('Sending message via ZeroMQ, size: %s bytes', len(data))
            
            # Send the message with all parts
            self.zmq_push.send_multipart(parts)
            log.debug(f"Successfully sent complete message of {len(data)} bytes from {sender_str} to ZeroMQ buffer")
        except OSError as e:
            log.error(f"OSError writing to ZeroMQ socket: {e}")
        except Exception as e:
            log.error(f"Error writing to ZeroMQ socket: {e}")
        
    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-GCM."""
        return aes_gcm_encrypt(self.shared_key, data)
    
    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt data using AES-GCM."""
        return aes_gcm_decrypt(self.shared_key, data)
    
    def sendto(self, data: bytes, address: Tuple[str, int]) -> int:
        """Send data to the specified address."""
        if self.is_closed:
            return 0
        return self.socket.sendto(data, address)
    
    def close(self) -> None:
        """Mark the backend as closed."""
        self.is_closed = True 