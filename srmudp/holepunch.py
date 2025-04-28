from typing import Optional, Tuple, Any
import socket as s
from select import select
from time import time, sleep
from hashlib import sha256
from binascii import a2b_hex
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
import os
from .crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt

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

class HolePuncher:
    """
    Handles UDP hole punching and key exchange for secure peer-to-peer connections.
    """
    def __init__(self, family: int = s.AF_INET, timeout: float = 21.0, span: float = 3.0) -> None:
        self.family = family
        self.timeout = timeout
        self.span = span

    def _find_mtu_size(self, sock: s.socket, address: Tuple[str, int], timeout: float) -> int:
        """
        Determine MTU size for the connection path.
        First tries platform-specific methods, then falls back to a probe-based approach.
        If all fails, returns a conservative default value.
        """
        # Default conservative MTU values
        DEFAULT_MTU_IPV4 = 1400  # Conservative for most IPv4 networks (normal 1500)
        DEFAULT_MTU_IPV6 = 1280  # Minimum MTU required for IPv6
        
        # Try platform-specific method first
        try:
            # On Linux, we can get the path MTU directly
            if hasattr(s, 'IP_MTU') and hasattr(s, 'IPPROTO_IP'):
                return sock.getsockopt(s.IPPROTO_IP, s.IP_MTU)
        except (AttributeError, OSError) as e:
            # Not supported or failed
            pass
        
        # Fall back to probe-based approach with better error handling
        try:
            wait = 0.05
            mut = 1472  # max ipv4:1472b, ipv6:1452b
            receive_size = 0
            my_mut_size = None
            finished_notify = False
            for _ in range(int(min(timeout, 5) / wait)):  # Cap to 5 seconds max
                r, _w, _x = select([sock.fileno()], [], [], wait)
                if r:
                    data, _addr = sock.recvfrom(1500)
                    if data.startswith(b'#####'):
                        if len(data) < receive_size:
                            sock.sendto(receive_size.to_bytes(4, 'little'), address)
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
                            sock.sendto(b'#' * mut, address)
                    except s.error:
                        pass
                    mut -= 16
                else:
                    pass
            
            # If we got a reasonable receive size but no explicit MTU
            if receive_size > 1024:
                return receive_size - 48  # Conservative estimate (IP+UDP headers, etc.)
        
        except Exception as e:
            # Log but don't fail
            if logger:
                logger.warning(f"MTU discovery failed: {e}, using default value")
        
        # If all else fails, use safe default based on socket family
        if sock.family == s.AF_INET6:
            return DEFAULT_MTU_IPV6
        else:
            return DEFAULT_MTU_IPV4

    def establish_connection(
        self,
        sock: s.socket,
        remote_addr: Tuple[str, int],
        logger: Any = None,
    ) -> Tuple[bytes, Tuple[str, int], int, bytes, bytes]:
        """
        Führt UDP-Hole-Punching und Key-Exchange durch.
        Gibt zurück:
            shared_key: bytes
            peer_address: Tuple[str, int]
            mtu: int
            my_public_key: bytes
            peer_public_key: bytes
        """
        timeout = self.timeout
        span = self.span
        address = remote_addr
        log = logger or (lambda *a, **k: None)
        curve_name = 'P-256'
        punch_msg = b"udp hole punching"
        check_msg = b"success hand shake"

        # my secret & public key
        my_key = ECC.generate(curve=curve_name)
        my_pk_pem = my_key.public_key().export_key(format='PEM')
        my_pk_pem_bytes = my_pk_pem.encode('utf-8')
        other_pk: Optional[ECC.EccKey] = None
        peer_pk_bytes: Optional[bytes] = None
        shared_key: Optional[bytes] = None
        session_key: Optional[bytes] = None

        # 1. UDP hole punching
        sock.sendto(S_HOLE_PUNCHING + punch_msg + curve_name.encode(), address)

        for _ in range(int(timeout / span)):
            r, _w, _x = select([sock.fileno()], [], [], span)
            if r:
                data, _addr = sock.recvfrom(1024)
                stage, data = data[:1], data[1:]

                if stage == S_HOLE_PUNCHING:
                    received_curve_name = data.replace(punch_msg, b'').decode()
                    assert curve_name == received_curve_name, ("different curve", curve_name, received_curve_name)
                    sock.sendto(S_SEND_PUBLIC_KEY + my_pk_pem_bytes, address)
                    if logger:
                        logger.debug("success UDP hole punching")

                elif stage == S_SEND_PUBLIC_KEY:
                    other_pk = ECC.import_key(data)
                    peer_pk_bytes = data
                    shared_point = other_pk.pointQ * my_key.d
                    coord_len = (shared_point.size_in_bits() + 7) // 8
                    temp_shared_key = SHA256.new(shared_point.x.to_bytes(coord_len, 'big') + shared_point.y.to_bytes(coord_len, 'big')).digest()
                    session_key = os.urandom(32)
                    shared_key = temp_shared_key
                    encrypted_session_key = aes_gcm_encrypt(shared_key, session_key)
                    shared_key = session_key
                    separator = b'|KEY|'
                    encrypted_data_payload = my_pk_pem_bytes + separator + encrypted_session_key.hex().encode('utf-8')
                    sock.sendto(S_SEND_SHARED_KEY + encrypted_data_payload, address)
                    if logger:
                        logger.debug("success deriving ECDH key and sending encrypted session key")

                elif stage == S_SEND_SHARED_KEY:
                    separator = b'|KEY|'
                    parts = data.split(separator, 1)
                    if len(parts) != 2:
                        raise ConnectionError("Invalid S_SEND_SHARED_KEY format")
                    peer_pk_pem_bytes = parts[0]
                    encrypted_session_key_hex = parts[1].decode('utf-8')
                    if other_pk is None:
                        other_pk = ECC.import_key(peer_pk_pem_bytes)
                        peer_pk_bytes = peer_pk_pem_bytes
                    else:
                        # Priority check is needed when both sides send their public keys
                        log.debug("need to check priority because already got other's pk")
                        my_pri = sha256(my_pk_pem_bytes + peer_pk_pem_bytes).digest()
                        other_pri = sha256(peer_pk_pem_bytes + my_pk_pem_bytes).digest()

                        if my_pri < other_pri:
                            log.debug("my priority is LOW and process received session key")
                        elif other_pri < my_pri:
                            log.debug("my priority is HIGH and ignore this command (use my session key)")
                            continue
                        else:
                            raise ConnectionError("my and other's key is same, this means you connect to yourself")
                    shared_point = other_pk.pointQ * my_key.d
                    coord_len = (shared_point.size_in_bits() + 7) // 8
                    derived_key = SHA256.new(shared_point.x.to_bytes(coord_len, 'big') + shared_point.y.to_bytes(coord_len, 'big')).digest()
                    shared_key = derived_key
                    decrypted_session_key = aes_gcm_decrypt(shared_key, a2b_hex(encrypted_session_key_hex))
                    shared_key = decrypted_session_key
                    sock.sendto(S_ESTABLISHED + aes_gcm_encrypt(shared_key, check_msg), address)
                    if logger:
                        logger.debug("success decrypt session key")
                    break

                elif stage == S_ESTABLISHED:
                    decrypt_msg = aes_gcm_decrypt(shared_key, data)
                    if decrypt_msg != check_msg:
                        raise ConnectionError("failed to check establish message")
                    if logger:
                        logger.debug("successful handshake")
                    break
                else:
                    raise ConnectionError(f"not defined message received {len(data)} bytes")
        else:
            raise ConnectionError("timeout on handshake")

        # MTU Discovery
        sock.setsockopt(s.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        mtu = self._find_mtu_size(sock, address, timeout)
        sock.setsockopt(s.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
        if logger:
            logger.debug(f"success get MUT size {mtu}b")

        return shared_key, address, mtu, my_pk_pem_bytes, peer_pk_bytes 