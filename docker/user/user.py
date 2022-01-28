import sys
import pickle
import random
import socket
import logging
import numpy as np

from utils import *


class User:
    def __init__(self, id: str, pub_key: bytes, priv_key: bytes):
        self.id = id
        self.port = 10001

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

        self.U_3 = None

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

    def send(self, msg: bytes, host: str, port: int):
        """Sends message to host:port.

        Args:
            msg (bytes): the message to be sent.
            host (str): the target host.
            port (int): the target port.
        """

        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.connect((host, port))

        SocketUtil.send_msg(sock, msg)

        sock.close()

    def listen_global_weights(self):
        """Listens to the server for the weights of the global model.

        Returns:
            list: the weights of the global model.
        """

        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        sock.bind(("", self.port))
        sock.listen()

        conn, _ = sock.accept()

        data = SocketUtil.recv_msg(conn)
        global_weights = pickle.loads(data)

        logging.info("received global weights from the server")

        sock.close()

        return global_weights

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
        self.U_1 = list(self.ka_pub_keys_map.keys())

        logging.info("received all signatures from the server")

        sock.close()

    def gen_shares(self, U_1: list, t: int, host: str, port: int):
        """Generates random seed for a PRG, generates t-out-of-U1 shares of the s_sk and random seed,
           and encrypts these shares using the shared key of the two users.

        Args:
            U_1 (list): all users who have sent DH key pairs.
            t (int): the threshold value of secret sharing scheme.
            host (str): the server's host.
            port (int): the server's port used to receive these shares.
        """

        # generates a random integer from 0 to 2**32 - 1 (to be used as a seed for PRG)
        self.__random_seed = random.randint(0, 2**32 - 1)

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
        self.send(msg, host, port)

        logging.info("successfully generated shares")

    def listen_ciphertexts(self):
        """Listens to the server for the ciphertexts.
        """

        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        sock.bind(("", self.port))
        sock.listen()

        conn, _ = sock.accept()

        data = SocketUtil.recv_msg(conn)
        self.ciphertexts = pickle.loads(data)

        logging.info("received ciphertext from the server")

        sock.close()

    def mask_gradients(self, gradients: np.ndarray, host: str, port: int):
        """Masks user's own gradients and sends them to the server.

        Args:
            gradients (np.ndarray): user's raw gradients.
            host (str): the server's host.
            port (int): the server's port used to receive the masked gradients.
        """

        U_2 = list(self.ciphertexts.keys())

        # generate user's own private mask vector p_u
        priv_mask_vec = []
        for g in gradients:
            rs = np.random.RandomState(self.__random_seed)
            priv_mask_vec.append(rs.random(g.shape))

        # generate random vectors p_u_v for each user
        random_vec_list = []
        for v in U_2:
            if v == self.id:
                continue

            v_s_pk = self.ka_pub_keys_map[v]["s_pk"]
            shared_key = KA.agree(self.__s_sk, v_s_pk)

            if int(self.id) > int(v):
                random_vec = []
                for g in gradients:
                    random.seed(shared_key)
                    rs = np.random.RandomState(random.randint(0, 2**32 - 1))
                    random_vec.append(rs.random(g.shape))
                random_vec_list.append(random_vec)
            else:
                random_vec = []
                for g in gradients:
                    random.seed(shared_key)
                    rs = np.random.RandomState(random.randint(0, 2**32 - 1))
                    random_vec.append(-rs.random(g.shape))
                random_vec_list.append(random_vec)

        masked_gradients = np.sum([gradients, priv_mask_vec, np.sum(random_vec_list, axis=0)], axis=0)

        msg = pickle.dumps([self.id, masked_gradients])

        # send the masked gradients to the server
        self.send(msg, host, port)

    def consistency_check(self, host: str, port: int):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        sock.bind(("", self.port))
        sock.listen()

        conn, _ = sock.accept()

        data = SocketUtil.recv_msg(conn)
        self.U_3 = pickle.loads(data)

        logging.info("received U_3 from the server")

        signature = SIG.sign(data, self.__priv_key)
        msg = pickle.dumps([self.id, signature])

        self.send(msg, host, port)

        logging.info("send signature to the server")

        conn, _ = sock.accept()
        data = SocketUtil.recv_msg(conn)
        signature_map = pickle.loads(data)

        for key, value in signature_map.items():
            res = SIG.verify(pickle.dumps(self.U_3), value, self.pub_key_map[key])

            if res is False:
                logging.error("user {}'s signature is wrong!".format(key))

                msg = pickle.dumps(self.id)
                self.send(msg, host, port)

                sys.exit(1)

        sock.close()

    def unmask_gradients(self, host: str, port: str):
        """Sends the shares of offline users' private key and online users' random seed to the server.

        Args:
            host (str): the server's host.
            port (str): the server's port used to receive the shares.
        """

        U_2 = list(self.ciphertexts.keys())

        priv_key_shares_map = {}
        random_seed_shares_map = {}

        for v in U_2:
            if self.id == v:
                continue

            v_c_pk = self.ka_pub_keys_map[v]["c_pk"]
            shared_key = KA.agree(self.__c_sk, v_c_pk)

            info = pickle.loads(AE.decrypt(shared_key, shared_key, self.ciphertexts[v]))

            if v not in self.U_3:
                # send the shares of s_sk to the server
                priv_key_shares_map[v] = info[2]
            else:
                # send the shares of random seed to the server
                random_seed_shares_map[v] = info[3]

        msg = pickle.dumps([self.id, priv_key_shares_map, random_seed_shares_map])

        self.send(msg, host, port)
