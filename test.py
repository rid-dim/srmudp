from srudp import SecureReliableSocket, Packet
from concurrent.futures import ThreadPoolExecutor
from time import sleep
import socket as s
import random
import unittest
import asyncio
import logging
import os


logger = logging.getLogger("srudp")
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
        sock1 = SecureReliableSocket()
        sock2 = SecureReliableSocket()

        # connect
        fut1 = self.executor.submit(sock1.connect, ("127.0.0.1", self.port))
        fut2 = self.executor.submit(sock2.connect, ("127.0.0.1", self.port))

        fut1.result(10.0)
        fut2.result(10.0)

        # connection info
        assert sock1.getpeername() == sock2.getsockname(), (sock1.getpeername(), sock2.getsockname())

        logger.info("socket 1 peer: %s", sock1.getpeername())
        logger.info("socket 2 peer: %s", sock2.getpeername())
        logger.info("socket 1 established: %s", sock1.established)
        logger.info("socket 2 established: %s", sock2.established)

        # normal sending
        sock1.send(b"hello world")
        #sleep(0.01)
        logger.info("waiting for receive")
        rec = sock2.receive(timeout=1.0)
        logger.info("received: %s", rec)
        assert rec == b"hello world"

        # broadcast sending
        sock2.broadcast(b"good man")
        #sleep(0.01)
        logger.info("waiting for receive")
        rec = sock1.receive(timeout=1.0)
        logger.info("received: %s", rec)
        assert rec == b"good man"

        # broadcast hook fnc
        def hook_fnc(packet: Packet, _sock: SecureReliableSocket):
            assert packet.data == b"broadcasting now"
            logger.info("hook fnc called")
            logger.info("hook data: %s", packet.data)
        sock1.broadcast_hook_fnc = hook_fnc
        sock2.broadcast(b"broadcasting now")

        # close
        sock1.close()
        sock2.close()

    def test_big_size(self):
        logger.info("start test_big_size()")
        sock1 = SecureReliableSocket()
        sock2 = SecureReliableSocket()

        # connect
        fut1 = self.executor.submit(sock1.connect, ("127.0.0.1", self.port))
        fut2 = self.executor.submit(sock2.connect, ("127.0.0.1", self.port))

        fut1.result(10.0)
        fut2.result(10.0)

        # 1M bytes data
        data = os.urandom(1000000)
        self.executor.submit(sock2.send, data)\
            .add_done_callback(lambda fut: fut.result())


        received = sock1.receive()
        print(len(received))
        assert received == data, (len(received), len(data))

        # close
        sock1.close()
        sock2.close()

    def test_ipv6(self):
        logger.info("start test_ipv6()")
        # https://docs.travis-ci.com/user/reference/overview/#virtualisation-environment-vs-operating-system
        if True or IS_TRAVIS:
            return None #unittest.skip("ipv6 isn't supported")

        sock1 = SecureReliableSocket(s.AF_INET6)
        sock2 = SecureReliableSocket(s.AF_INET6)
        sock1.settimeout(5.0)
        sock2.settimeout(5.0)

        # connect
        fut1 = self.executor.submit(sock1.connect, ("::1", self.port))
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
