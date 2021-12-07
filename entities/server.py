import pickle
import socket
import logging
import socketserver

from utils import SocketUtil


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

        logging.info("[%d/%d] | received %s's signature", received_num, self.user_num, self.client_address[0])


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

        logging.info("[%d/%d] | received %s's ciphertexts", received_num, self.U_1_num, self.client_address[0])


class MaskedGradientsRequestHandler(socketserver.BaseRequestHandler):
    U_2_num = 0
    masked_gradients_list = []
    U_3 = []

    def handle(self) -> None:
        # receive data from the client
        data = SocketUtil.recv_msg(self.request)

        msg = pickle.loads(data)

        self.U_3.append(msg[0])
        self.masked_gradients_list.append(msg[1])

        received_num = len(self.U_3)

        logging.info("[%d/%d] | received %s's masked gradients", received_num, self.U_2_num, self.client_address[0])


class ConsistencyCheckRequestHandler(socketserver.BaseRequestHandler):
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

        logging.info("[%d/%d] | received %s's consistency check", received_num, self.U_3_num, self.client_address[0])


class Server:
    def __init__(self):
        self.id = "0"
        self.host = socket.gethostname()
        self.broadcast_port = 10000
        self.signature_port = 20000
        self.ss_port = 20001
        self.masked_gradients_port = 20002
        self.consistency_check_port = 20003

        self.signature_server = socketserver.ThreadingTCPServer(
            (self.host, self.signature_port), SignatureRequestHandler)
        self.ss_server = socketserver.ThreadingTCPServer(
            (self.host, self.ss_port), SecretShareRequestHandler)
        self.masked_gradients_server = socketserver.ThreadingTCPServer(
            (self.host, self.masked_gradients_port), MaskedGradientsRequestHandler)
        self.consistency_check_server = socketserver.ThreadingTCPServer(
            (self.host, self.consistency_check_port), ConsistencyCheckRequestHandler)

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
        sock.connect((host, port))

        SocketUtil.send_msg(sock, msg)

        sock.close()
