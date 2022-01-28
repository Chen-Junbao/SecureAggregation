import pickle
import random
import socket
import logging
import socketserver
import numpy as np

from utils import *
from threading import Thread

# compatible with Windows
socket.SO_REUSEPORT = socket.SO_REUSEADDR


class SignatureRequestHandler(socketserver.BaseRequestHandler):
    user_num = 0
    ka_pub_keys_map = {}    # {id: {c_pk: bytes, s_pk, bytes, signature: bytes}}
    U_1 = []

    def handle(self) -> None:
        # receive data from the client
        data = SocketUtil.recv_msg(self.request)

        msg = pickle.loads(data)
        id = msg["id"]
        del msg["id"]

        SignatureRequestHandler.ka_pub_keys_map[id] = msg
        SignatureRequestHandler.U_1.append(id)

        received_num = len(SignatureRequestHandler.U_1)

        logging.info("[%d/%d] | received user %s's signature", received_num, SignatureRequestHandler.user_num, id)


class SecretShareRequestHandler(socketserver.BaseRequestHandler):
    U_1_num = 0
    ciphertexts_map = {}         # {u:{v1: ciphertexts, v2: ciphertexts}}
    U_2 = []

    def handle(self) -> None:
        # receive data from the client
        data = SocketUtil.recv_msg(self.request)

        msg = pickle.loads(data)
        id = msg[0]

        # retrieve each user's ciphertexts
        for key, value in msg[1].items():
            if key not in SecretShareRequestHandler.ciphertexts_map:
                SecretShareRequestHandler.ciphertexts_map[key] = {}
            SecretShareRequestHandler.ciphertexts_map[key][id] = value

        SecretShareRequestHandler.U_2.append(id)

        received_num = len(SecretShareRequestHandler.U_2)

        logging.info("[%d/%d] | received user %s's ciphertexts", received_num, SecretShareRequestHandler.U_1_num, id)


class MaskingRequestHandler(socketserver.BaseRequestHandler):
    U_2_num = 0
    masked_gradients_list = []
    U_3 = []

    def handle(self) -> None:
        # receive data from the client
        data = SocketUtil.recv_msg(self.request)

        msg = pickle.loads(data)
        id = msg[0]

        self.U_3.append(msg[0])
        self.masked_gradients_list.append(msg[1])

        received_num = len(self.U_3)

        logging.info("[%d/%d] | received user %s's masked gradients", received_num, self.U_2_num, id)


class ConsistencyRequestHandler(socketserver.BaseRequestHandler):
    U_3_num = 0
    consistency_check_map = {}
    U_4 = []
    status_list = []    # the ids of users who fails in consistency check

    def handle(self) -> None:
        data = SocketUtil.recv_msg(self.request)

        msg = pickle.loads(data)

        if len(msg) == 2:
            id = msg[0]

            ConsistencyRequestHandler.U_4.append(id)
            ConsistencyRequestHandler.consistency_check_map[id] = msg[1]

            received_num = len(ConsistencyRequestHandler.U_4)

            logging.info("[%d/%d] | received user %s's consistency check",
                         received_num, ConsistencyRequestHandler.U_3_num, id)
        else:
            ConsistencyRequestHandler.status_list.append(msg)
            ConsistencyRequestHandler.U_4.append(msg)

            logging.info("received user %s's wrong consistency check!", msg)


class UnmaskingRequestHandler(socketserver.BaseRequestHandler):
    U_4_num = 0
    priv_key_shares_map = {}        # {id: []}
    random_seed_shares_map = {}     # {id: []}
    U_5 = []

    def handle(self) -> None:
        data = SocketUtil.recv_msg(self.request)

        msg = pickle.loads(data)
        id = msg[0]

        # retrieve the private key shares
        for key, value in msg[1].items():
            if key not in UnmaskingRequestHandler.priv_key_shares_map:
                UnmaskingRequestHandler.priv_key_shares_map[key] = []
            UnmaskingRequestHandler.priv_key_shares_map[key].append(value)

        # retrieve the ramdom seed shares
        for key, value in msg[2].items():
            if key not in UnmaskingRequestHandler.random_seed_shares_map:
                UnmaskingRequestHandler.random_seed_shares_map[key] = []
            UnmaskingRequestHandler.random_seed_shares_map[key].append(value)

        UnmaskingRequestHandler.U_5.append(id)

        received_num = len(UnmaskingRequestHandler.U_5)

        logging.info("[%d/%d] | received user %s's shares", received_num, UnmaskingRequestHandler.U_4_num, id)


class Server:
    def __init__(self):
        self.id = "0"
        self.host = socket.gethostname()
        self.broadcast_port = 10000
        self.signature_port = 20000
        self.ss_port = 20001
        self.masking_port = 20002
        self.consistency_port = 20003
        self.unmasking_port = 20004

        socketserver.ThreadingTCPServer.allow_reuse_address = True
        socketserver.ThreadingTCPServer.request_queue_size = 128    # The size of the request queue

        self.signature_server = socketserver.ThreadingTCPServer(
            ("0.0.0.0", self.signature_port), SignatureRequestHandler)
        self.ss_server = socketserver.ThreadingTCPServer(
            ("0.0.0.0", self.ss_port), SecretShareRequestHandler)
        self.masking_server = socketserver.TCPServer(
            ("0.0.0.0", self.masking_port), MaskingRequestHandler)
        self.consistency_server = socketserver.ThreadingTCPServer(
            ("0.0.0.0", self.consistency_port), ConsistencyRequestHandler)
        self.unmasking_server = socketserver.ThreadingTCPServer(
            ("0.0.0.0", self.unmasking_port), UnmaskingRequestHandler)

    def serve_all(self):
        signature_thread = Thread(target=self.signature_server.serve_forever)
        ss_thread = Thread(target=self.ss_server.serve_forever)
        masking_thread = Thread(target=self.masking_server.serve_forever)
        consistency_thread = Thread(target=self.consistency_server.serve_forever)
        unmasking_thread = Thread(target=self.unmasking_server.serve_forever)

        signature_thread.daemon = True
        signature_thread.start()
        ss_thread.daemon = True
        ss_thread.start()
        masking_thread.daemon = True
        masking_thread.start()
        consistency_thread.daemon = True
        consistency_thread.start()
        unmasking_thread.daemon = True
        unmasking_thread.start()

        logging.info("start all servers")

    def close_all(self):
        self.signature_server.server_close()
        self.ss_server.server_close()
        self.masking_server.server_close()
        self.consistency_server.server_close()
        self.unmasking_server.server_close()

        logging.info("stop all servers")

    def clean(self):
        SignatureRequestHandler.ka_pub_keys_map = {}
        SignatureRequestHandler.U_1 = []
        SecretShareRequestHandler.ciphertexts_map = {}
        SecretShareRequestHandler.U_2 = []
        MaskingRequestHandler.masked_gradients_list = []
        MaskingRequestHandler.U_3 = []
        ConsistencyRequestHandler.consistency_check_map = {}
        ConsistencyRequestHandler.U_4 = []
        ConsistencyRequestHandler.status_list = []
        UnmaskingRequestHandler.priv_key_shares_map = {}
        UnmaskingRequestHandler.random_seed_shares_map = {}
        UnmaskingRequestHandler.U_5 = []

    def broadcast_signatures(self, port: int):
        """Broadcasts all users' key pairs and corresponding signatures.

        Args:
            port (int): the port used to broadcast the message.
        """

        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # reuse port so we will be able to run multiple clients on single (host, port).
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        # enable broadcasting mode
        server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        data = pickle.dumps(SignatureRequestHandler.ka_pub_keys_map)

        SocketUtil.broadcast_msg(server, data, port)

        logging.info("broadcasted all signatures.")

        server.close()

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

    def unmask(self, shapes: list) -> np.ndarray:
        """Unmasks gradients by reconstructing random vectors and private mask vectors.

        Args:
            shapes (list): the shapes of the raw gradients.

        Returns:
            np.ndarray: the sum of the raw gradients.
        """

        # reconstruct random vectors p_v_u
        recon_random_vec_list = []
        for u in SecretShareRequestHandler.U_2:
            if u not in MaskingRequestHandler.U_3:
                # the user drops out, reconstruct its private keys and then generate the corresponding random vectors
                priv_key = SS.recon(UnmaskingRequestHandler.priv_key_shares_map[u])
                for v in MaskingRequestHandler.U_3:
                    shared_key = KA.agree(priv_key, SignatureRequestHandler.ka_pub_keys_map[v]["s_pk"])

                    if int(u) > int(v):
                        recon_random_vec = []
                        for shape in shapes:
                            random.seed(shared_key)
                            rs = np.random.RandomState(random.randint(0, 2**32 - 1))
                            recon_random_vec.append(rs.random(shape))
                        recon_random_vec_list.append(recon_random_vec)
                    else:
                        recon_random_vec = []
                        for shape in shapes:
                            random.seed(shared_key)
                            rs = np.random.RandomState(random.randint(0, 2**32 - 1))
                            recon_random_vec.append(-rs.random(shape))
                        recon_random_vec_list.append(recon_random_vec)

        # reconstruct private mask vectors p_u
        recon_priv_vec_list = []
        for u in MaskingRequestHandler.U_3:
            priv_mask_vec = []
            for shape in shapes:
                random_seed = SS.recon(UnmaskingRequestHandler.random_seed_shares_map[u])
                rs = np.random.RandomState(random_seed)
                priv_mask_vec.append(rs.random(shape))

            recon_priv_vec_list.append(priv_mask_vec)

        masked_gradients = np.sum(MaskingRequestHandler.masked_gradients_list, axis=0)
        num = len(MaskingRequestHandler.masked_gradients_list)
        recon_priv_vec_sum = np.sum(recon_priv_vec_list, axis=0)
        recon_random_vec_sum = np.sum(recon_random_vec_list, axis=0)

        output = np.sum([masked_gradients, -recon_priv_vec_sum, recon_random_vec_sum], axis=0) / num

        return output
