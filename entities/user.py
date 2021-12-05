import logging
import pickle
import random
import socket

from utils import *
from threading import Thread


class User:
    def __init__(self, id: str, pub_key: bytes, priv_key: bytes):
        self.id = id
        self.port = int("1" + id.zfill(4))

        self.pub_key = pub_key
        self.__priv_key = priv_key
        self.pub_key_map = []

        self.c_pk = None
        self.__c_sk = None
        self.s_pk = None
        self.__s_sk = None

        self.ka_pub_keys_map = None

        self.__random_seed = None

        self.ciphertexts = None

    def gen_DH_pairs(self):
        self.c_pk, self.__c_sk = KA.gen()
        self.s_pk, self.__s_sk = KA.gen()

    def gen_signature(self):
        msg = pickle.dumps([self.c_pk, self.s_pk])
        signature = SIG.sign(msg, self.__priv_key)

        return signature

    def ver_signature(self) -> bool:
        status = True
        for key, value in self.ka_pub_keys_map.items():
            msg = pickle.dumps([value["c_pk"], value["s_pk"]])

            res = SIG.verify(msg, value["signature"], self.pub_key_map[key])

            if res is False:
                status = False
                logging.error("user {}'s signature is wrong!".format(key))

        return status

    def send(self, data: bytes, host: str, port: int):
        """Sends data to host:port.

        Args:
            data (bytes): the data to be sent.
            host (str): the target host.
            port (int): the target port.
        """

        sock = socket.socket()
        sock.connect((host, port))

        SocketUtil.send_msg(sock, data)

        sock.close()

    def listen_broadcast(self, port: int):
        """Listens to the server's broadcast, and saves all users' key pairs and corresponding signatures.

        Args:
            port (int): the port used to broadcast the message.
        """

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # reuse port so we will be able to run multiple clients on single (host, port).
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        # enable broadcasting mode
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        sock.bind(("", port))

        data = SocketUtil.recv_broadcast(sock)

        self.ka_pub_keys_map = pickle.loads(data)

        logging.info("received all signatures from the server")

        sock.close()

    def gen_shares(self, U_1: list, t: int, host: str, ss_port: int):
        """Generates random seed for a PRG, generates t-out-of-U1 shares of the s_sk and random seed,
           and encrypts these shares using the shared key of the two users.

        Args:
            U_1 (list): all users who have sent DH key pairs.
            t (int): the threshold value of secret sharing scheme.
            host (str): the target host.
            ss_port (int): the target port.
        """

        # generates a random integer from - 2^20 to 2^20 (to be used as a seed for PRG)
        self.__random_seed = random.randint(-2**20, 2**20)

        n = len(U_1)

        s_sk_shares = SS.share(self.__s_sk, t, n)
        random_seed_shares = SS.share(self.__random_seed, t, n)

        all_ciphertexts = {}       # {id: ciphertext}

        for i, v in enumerate(U_1):
            if v == self.id:
                continue

            info = pickle.dumps([self.id, v, s_sk_shares[i], random_seed_shares[i]])

            v_c_pk = self.ka_pub_keys_map[v]["c_pk"]
            shared_key = KA.agree(self.__c_sk, v_c_pk)

            ciphertext = AE.encrypt(shared_key, shared_key, info)

            all_ciphertexts[v] = ciphertext

        msg = pickle.dumps([self.id, all_ciphertexts])

        # send all shares of the s_sk and random seed to the server
        self.send(msg, host, ss_port)

    def listen_ciphertexts(self):
        """Listens to the server for the ciphertexts.
        """
        sock = socket.socket()

        sock.bind(("", self.port))
        sock.listen()

        conn, _ = sock.accept()

        data = SocketUtil.recv_msg(conn)

        self.ciphertexts = pickle.loads(data)

        logging.info("received ciphertext from the server")
