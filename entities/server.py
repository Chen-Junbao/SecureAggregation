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

        SignatureRequestHandler.ka_pub_keys_map[id] = msg
        SignatureRequestHandler.U_1.append(id)

        received_num = len(SignatureRequestHandler.U_1)

        logging.info("[%d/%d] | received %s's signature", received_num,
                     SignatureRequestHandler.user_num, self.client_address[0])


class SecretShareRequestHandler(socketserver.BaseRequestHandler):
    U_1_num = 0
    ciphertexts_map = {}         # {id: ciphertexts}
    U_2 = []

    def handle(self) -> None:
        # receive data from the client
        data = SocketUtil.recv_msg(self.request)

        msg = pickle.loads(data)
        id = msg[0]

        SecretShareRequestHandler.ciphertexts_map[id] = msg[1]
        SecretShareRequestHandler.U_2.append(id)

        received_num = len(SecretShareRequestHandler.U_2)

        logging.info("[%d/%d] | received %s's ciphertexts", received_num,
                     SecretShareRequestHandler.U_1_num, self.client_address[0])


class Server:
    def __init__(self):
        self.id = "0"
        self.host = socket.gethostname()
        self.broadcast_port = 10000
        self.signature_port = 20000
        self.ss_port = 20001

        self.signature_server = socketserver.ThreadingTCPServer(
            (self.host, self.signature_port), SignatureRequestHandler)
        self.ss_server = socketserver.ThreadingTCPServer(
            (self.host, self.ss_port), SecretShareRequestHandler)

    def broadcast_signatures(self, port: int) -> list:
        """Broadcasts all users' key pairs and corresponding signatures.

        Args:
            port (int): the port used to broadcast the message.

        Returns:
            list: ids of all online users。
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

        return SignatureRequestHandler.U_1
