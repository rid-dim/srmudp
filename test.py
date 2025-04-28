from srmudp import SecureReliableSocket, Packet
from concurrent.futures import ThreadPoolExecutor
from time import sleep
import socket as s
import random
import unittest
import asyncio
import logging
import os


logger = logging.getLogger("srmudp")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '[%(levelname)-6s] [%(threadName)-10s] [%(asctime)-24s] %(message)s')
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(formatter)
logger.addHandler(sh)

IS_TRAVIS = os.getenv('TRAVIS') == 'true'
IS_WINDOWS = os.name == 'nt'


class TestSocket(unittest.TestCase):
    def setUp(self) -> None:
        logger.info("start")
        self.port = random.randint(10000, 30000)
        logger.info("port: %d", self.port)
        self.executor = ThreadPoolExecutor(4, thread_name_prefix="Thread")

    def tearDown(self) -> None:
        self.executor.shutdown(True)
        logger.info("end")

    def test_basic(self):
        logger.info("start test_basic()")
        sock1 = SecureReliableSocket(self.port)
        sock2 = SecureReliableSocket(self.port+1)

        # connect
        fut1 = self.executor.submit(sock1.connect, f"127.0.0.1:{sock2.port}")
        fut2 = self.executor.submit(sock2.connect, f"127.0.0.1:{sock1.port}")

        fut1.result(10.0)
        fut2.result(10.0)

        # connection info
        logger.info("socket 1 peer: %s", sock1.getpeername())
        logger.info("socket 2 peer: %s", sock2.getpeername())
        logger.info("socket 1 name: %s", sock1.getsockname())
        logger.info("socket 2 name: %s", sock2.getsockname())
        logger.info("socket 1 established: %s", sock1.established)
        logger.info("socket 2 established: %s", sock2.established)
        
        # Prüfe, ob die Verbindungen korrekt sind
        peer1 = sock1.getpeername()
        name2 = sock2.getsockname()
        logger.info(f"Testing: socket1.peer ({peer1}) == socket2.name ({name2})")
        assert peer1 == name2.replace('0.0.0.0', '127.0.0.1'), (peer1, name2)

        # normal sending
        logger.info("Sending message from sock1 to sock2")
        sock1.send(b"hello world")
        #sleep(0.01)
        logger.info("waiting for receive")
        result = sock2.receive(timeout=1.0)
        if not result:
            self.fail("Keine Nachricht empfangen")
        sender, received_data, sender_key = result
        logger.info("received: %s from %s", received_data, sender)
        if sender_key:
            logger.info("sender's public key received: %d bytes", len(sender_key))
        assert received_data == b"hello world"
        sock1_name = sock1.getsockname()
        logger.info(f"Asserting sender ({sender}) == sock1.name ({sock1_name})")
        assert sender == sock1_name.replace('0.0.0.0', '127.0.0.1'), (sender, sock1_name)

        # broadcast sending
        sock2.broadcast(b"good man")
        #sleep(0.01)
        logger.info("waiting for receive")
        result = sock1.receive(timeout=1.0)
        if not result:
            self.fail("Keine Broadcast-Nachricht empfangen")
        sender, received_data, sender_key = result
        logger.info("received: %s from %s", received_data, sender)
        if sender_key:
            logger.info("sender's public key received: %d bytes", len(sender_key))
        assert received_data == b"good man"
        assert sender == sock2.getsockname().replace('0.0.0.0', '127.0.0.1'), (sender, sock2.getsockname())

        # broadcast hook fnc
        def hook_fnc(packet: Packet, sender_address, _sock: SecureReliableSocket):
            assert packet.data == b"broadcasting now"
            sender_str = f"{sender_address[0]}:{sender_address[1]}"
            assert sender_str == sock2.getsockname().replace('0.0.0.0', '127.0.0.1'), (sender_str, sock2.getsockname())
            logger.info("hook fnc called")
            logger.info("hook data: %s", packet.data)
        sock1.broadcast_hook_fnc = hook_fnc
        sock2.broadcast(b"broadcasting now")

        # close
        sock1.close()
        sock2.close()

    def test_big_size(self):
        logger.info("start test_big_size()")
        sock1 = SecureReliableSocket(self.port)
        sock2 = SecureReliableSocket(self.port+1)

        # connect
        fut1 = self.executor.submit(sock1.connect, f"127.0.0.1:{sock2.port}")
        fut2 = self.executor.submit(sock2.connect, f"127.0.0.1:{sock1.port}")

        fut1.result(10.0)
        fut2.result(10.0)

        # 1M bytes data
        data = os.urandom(1000000)
        self.executor.submit(sock2.send, data)\
            .add_done_callback(lambda fut: fut.result())

        result = sock1.receive(timeout=2.0)
        if not result:
            self.fail("Keine große Nachricht empfangen")
        sender, received_data, sender_key = result
        print(len(received_data))
        assert received_data == data, (len(received_data), len(data))
        assert sender == sock2.getsockname().replace('0.0.0.0', '127.0.0.1'), (sender, sock2.getsockname())
        if sender_key:
            logger.info("sender's public key received: %d bytes", len(sender_key))

        # close
        sock1.close()
        sock2.close()

    def test_ipv6(self):
        logger.info("start test_ipv6()")
        # https://docs.travis-ci.com/user/reference/overview/#virtualisation-environment-vs-operating-system
        if True or IS_TRAVIS:
            return None #unittest.skip("ipv6 isn't supported")

        sock1 = SecureReliableSocket(self.port, s.AF_INET6)
        sock2 = SecureReliableSocket(self.port+1, s.AF_INET6)
        sock1.settimeout(5.0)
        sock2.settimeout(5.0)

        # connect
        fut1 = self.executor.submit(sock1.connect, ("::1", self.port+1))
        sleep(1.0)
        fut2 = self.executor.submit(sock2.connect, ("::1", self.port))

        fut1.result(10.0)
        fut2.result(10.0)

        assert sock1.established and sock2.established, (sock1, sock2)

        # close
        sock1.close()
        sock2.close()

if __name__ == "__main__":
    unittest.main()
