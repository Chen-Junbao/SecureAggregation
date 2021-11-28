import logging
import pickle
import socket

from utils import KA, SIG, SocketUtil


class User:
    def __init__(self, id: str, pub_key: bytes, priv_key: bytes):
        self.id = id
        self.port = int("1" + id.zfill(4))

        self.pub_key = pub_key
        self.__priv_key = priv_key
        self.pub_key_map = []

        self.c_pk = None
        self.c_sk = None
        self.s_pk = None
        self.s_sk = None

        self.socket = socket.socket()

    def gen_DH_pairs(self):
        self.c_pk, self.c_sk = KA.gen()
        self.s_pk, self.s_sk = KA.gen()

    def gen_signature(self):
        msg = pickle.dumps([self.c_pk, self.s_pk])
        signature = SIG.sign(msg, self.__priv_key)

        return signature

    def send(self, data: bytes, host: str, port: int):
        """Sends data to host:port.

        Args:
            data (bytes): the data to be sent.
            host (str): the target host.
            port (int): the target port.
        """

        self.socket.connect((host, port))

        SocketUtil.send_msg(self.socket, data)

        self.socket.close()

    def listen_broadcast(self, port: int):
        """Listens to the server's broadcast, and saves all users' key pairs and corresponding signatures.

        Args:
            port (int): the port used to broadcast the message.
        """

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # reuse port so we will be able to run multiple clients on single (host, port).
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        # enable broadcasting mode
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        client.bind(("", port))

        data = SocketUtil.recv_broadcast(client)

        self.signature_list = pickle.loads(data)

        logging.info("received all signatures from the server")

        client.close()
