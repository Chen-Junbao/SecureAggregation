import pickle
import random
import socket
import logging
import socketserver
import numpy as np

from utils import *

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

        self.ka_pub_keys_map[id] = msg
        self.U_1.append(id)

        received_num = len(self.U_1)

        logging.info("[%d/%d] | received user %s's signature", received_num, self.user_num, id)


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
            if key not in self.ciphertexts_map:
                self.ciphertexts_map[key] = {}
            self.ciphertexts_map[key][id] = value

        self.U_2.append(id)

        received_num = len(self.U_2)

        logging.info("[%d/%d] | received user %s's ciphertexts", received_num, self.U_1_num, id)


class MaskingRequestHandler(socketserver.BaseRequestHandler):
    U_2_num = 0
    masked_gradients_list = []
    verification_gradients_list = []
    U_3 = []

    def handle(self) -> None:
        # receive data from the client
        data = SocketUtil.recv_msg(self.request)

        msg = pickle.loads(data)
        id = msg[0]

        self.U_3.append(msg[0])
        self.masked_gradients_list.append(msg[1])
        self.verification_gradients_list.append(msg[2])

        received_num = len(self.U_3)

        logging.info("[%d/%d] | received user %s's masked gradients and verification gradients",
                     received_num, self.U_2_num, id)


class ConsistencyRequestHandler(socketserver.BaseRequestHandler):
    U_3_num = 0
    consistency_check_map = {}
    U_4 = []

    def handle(self) -> None:
        data = SocketUtil.recv_msg(self.request)

        msg = pickle.loads(data)
        id = msg[0]

        self.U_4.append(id)
        self.consistency_check_map[id] = msg[1]

        received_num = len(self.U_4)

        logging.info("[%d/%d] | received user %s's consistency check", received_num, self.U_3_num, id)


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
            if key not in self.priv_key_shares_map:
                self.priv_key_shares_map[key] = []
            self.priv_key_shares_map[key].append(value)

        # retrieve the ramdom seed shares
        for key, value in msg[2].items():
            if key not in self.random_seed_shares_map:
                self.random_seed_shares_map[key] = []
            self.random_seed_shares_map[key].append(value)

        self.U_5.append(id)

        received_num = len(self.U_5)

        logging.info("[%d/%d] | received user %s's shares", received_num, self.U_4_num, id)


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

        self.signature_server = socketserver.ThreadingTCPServer(
            (self.host, self.signature_port), SignatureRequestHandler)
        self.ss_server = socketserver.ThreadingTCPServer(
            (self.host, self.ss_port), SecretShareRequestHandler)
        self.masking_server = socketserver.ThreadingTCPServer(
            (self.host, self.masking_port), MaskingRequestHandler)
        self.consistency_server = socketserver.ThreadingTCPServer(
            (self.host, self.consistency_port), ConsistencyRequestHandler)
        self.unmasking_server = socketserver.ThreadingTCPServer(
            (self.host, self.unmasking_port), UnmaskingRequestHandler)

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

    def unmask(self, shape: tuple) -> np.ndarray:
        """Unmasks gradients by reconstructing random vectors and private mask vectors.
        Then, generates verification gradients by reconstructing random vectors and private mask vectors.

        Args:
            shape (tuple): the shape of the raw gradients.

        Returns:
            Tuple[np.ndarray, np.ndarray]: the sum of the raw gradients and verification gradients.
        """

        # reconstruct random vectors p_v_u_0 and p_u_v_1
        recon_random_vec_0_list = []
        recon_random_vec_1_list = []
        for u in SecretShareRequestHandler.U_2:
            if u not in MaskingRequestHandler.U_3:
                # the user drops out, reconstruct its private keys and then generate the corresponding random vectors
                priv_key = SS.recon(UnmaskingRequestHandler.priv_key_shares_map[u])
                for v in MaskingRequestHandler.U_3:
                    shared_key = KA.agree(priv_key, SignatureRequestHandler.ka_pub_keys_map[v]["s_pk"])

                    random.seed(shared_key)
                    s_u_v = random.randint(0, 2**32 - 1)

                    # expand s_u_v into two random vectors
                    rs = np.random.RandomState(s_u_v | 0)
                    p_u_v_0 = rs.random(shape)
                    rs = np.random.RandomState(s_u_v | 1)
                    p_u_v_1 = rs.random(shape)

                    if int(u) > int(v):
                        recon_random_vec_0_list.append(p_u_v_0)
                        recon_random_vec_1_list.append(p_u_v_1)
                    else:
                        recon_random_vec_0_list.append(-p_u_v_0)
                        recon_random_vec_1_list.append(-p_u_v_1)

        # reconstruct private mask vectors p_u_0 and p_u_1
        recon_priv_vec_0_list = []
        recon_priv_vec_1_list = []
        for u in MaskingRequestHandler.U_3:
            random_seed = SS.recon(UnmaskingRequestHandler.random_seed_shares_map[u])
            rs = np.random.RandomState(random_seed | 0)
            priv_mask_vec_0 = rs.random(shape)
            rs = np.random.RandomState(random_seed | 1)
            priv_mask_vec_1 = rs.random(shape)

            recon_priv_vec_0_list.append(priv_mask_vec_0)
            recon_priv_vec_1_list.append(priv_mask_vec_1)

        masked_gradients = np.sum(np.array(MaskingRequestHandler.masked_gradients_list), axis=0)
        recon_priv_vec_0 = np.sum(np.array(recon_priv_vec_0_list), axis=0)
        recon_random_vec_0 = np.sum(np.array(recon_random_vec_0_list), axis=0)

        output = masked_gradients - recon_priv_vec_0 + recon_random_vec_0

        verification_gradients = np.sum(np.array(MaskingRequestHandler.verification_gradients_list), axis=0)
        recon_priv_vec_1 = np.sum(np.array(recon_priv_vec_1_list), axis=0)
        recon_random_vec_1 = np.sum(np.array(recon_random_vec_1_list), axis=0)

        verification = verification_gradients - recon_priv_vec_1 + recon_random_vec_1

        return output, verification
