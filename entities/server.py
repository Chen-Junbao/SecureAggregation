import pickle
import struct
import socket
import logging
import socketserver

from utils import SocketUtil


class SignatureRequestHandler(socketserver.BaseRequestHandler):
    user_num = 0
    signature_list = []

    def handle(self) -> None:
        # receive data from the client
        data = SocketUtil.recv_msg(self.request)

        signature = pickle.loads(data)

        SignatureRequestHandler.signature_list.append(signature)

        received_num = len(SignatureRequestHandler.signature_list)

        logging.info("[%d/%d] | received %s's signature", received_num,
                     SignatureRequestHandler.user_num, self.client_address[0])


class Server:
    def __init__(self):
        self.id = "0"
        self.host = socket.gethostname()
        self.port = 10000

        self.tcp_server = socketserver.ThreadingTCPServer(
            (self.host, self.port), SignatureRequestHandler)

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

        data = pickle.dumps(SignatureRequestHandler.signature_list)

        SocketUtil.broadcast_msg(server, data, port)

        logging.info("broadcasted all signatures.")

        server.close()
