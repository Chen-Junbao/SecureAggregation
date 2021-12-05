import os
import rsa
import pickle
import struct
import multiprocessing

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from diffiehellman import DiffieHellman
from secretsharing import SecretSharer


class SIG:
    """Generates public and private keys, signs and verifies the message.
    """

    @staticmethod
    def gen(path: str = None, nbits=1024) -> tuple:
        """Generates public and private keys using RSA algorithm, and saves them.

        Args:
            path (str): path to store the public and private keys.
            nbits (int, optional): the number of bit used in RSA. Defaults to 1024.

        Returns:
            Tuple[PublicKey, PrivateKey]: the public and private keys.
        """

        pub_key, priv_key = rsa.newkeys(nbits, poolsize=multiprocessing.cpu_count())

        if path is not None:
            os.makedirs(path)

            # save the pub_key and priv_key
            with open(os.path.join(path, "pub.pem"), 'wb') as f:
                f.write(pub_key.save_pkcs1())
            with open(os.path.join(path, "priv.pem"), 'wb') as f:
                f.write(priv_key.save_pkcs1())

        return pub_key, priv_key

    @staticmethod
    def sign(msg: bytes, priv_key, hash_method="SHA-1"):
        return rsa.sign(msg, priv_key, hash_method)

    @staticmethod
    def verify(msg: bytes, signature: bytes, pub_key) -> bool:
        try:
            rsa.verify(msg, signature, pub_key)

            return True

        except rsa.VerificationError:
            return False


class AE:
    """Generates AES keys and nonces, encrypts and decrypts the message.
    """

    @staticmethod
    def gen(path: str = None) -> tuple:
        """Generates the key and nonce using AES algorithm (EAX mode), and saves them.

        Args:
            path (str): path to store the key and nonce.

        Returns:
            Tuple[key, nonce]: the key and nonce used to generate the cipher object.
        """

        key = get_random_bytes(16)
        nonce = get_random_bytes(16)

        if path is not None:
            os.makedirs(path)

            # save the key and nonce
            with open(os.path.join(path, "key"), 'wb') as f:
                f.write(key)
            with open(os.path.join(path, "nonce"), 'wb') as f:
                f.write(nonce)

        return key, nonce

    @staticmethod
    def encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)

        return ciphertext

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        return plaintext


class KA:
    """Generates public and private keys and computes the shared key.
    """

    @staticmethod
    def gen() -> tuple:
        """Generates Diffie-Hellman public and private keys.

        Returns:
            Tuple[PublicKey, PrivateKey]: the public and private keys.
        """

        dh = DiffieHellman()
        pub_key, priv_key = dh.get_public_key(), dh.get_private_key()

        return pub_key, priv_key

    @staticmethod
    def agree(priv_key: bytes, pub_key: bytes) -> bytes:
        """Generates the shared key of two users, and produce 256 bit digest of the shared key.

        Args:
            priv_key (bytes): the private key of one user.
            pub_key (bytes): the public key of the other user.

        Returns:
            bytes: the 256 bit shared key of the two users.
        """
        dh = DiffieHellman()

        dh.set_private_key(priv_key)
        shared_key = dh.generate_shared_key(pub_key)

        # in order to use AES, produce the 256 bit digest of the shared key using SHA-256
        h = SHA256.new()
        h.update(shared_key)
        key_256 = h.digest()

        return key_256


class SocketUtil:
    """Sends and receives messages using socket.
    """

    packet_size = 8192

    @staticmethod
    def send_msg(sock, msg):
        # add packet size
        msg = struct.pack('>I', len(msg)) + msg

        while msg is not None:
            if len(msg) > SocketUtil.packet_size:
                sock.send(msg[:SocketUtil.packet_size])
                msg = msg[SocketUtil.packet_size:]
            else:
                sock.send(msg)
                msg = None

    @staticmethod
    def broadcast_msg(sock, msg, port):
        # broadcast packet size
        sock.sendto(pickle.dumps(len(msg)), ('<broadcast>', port))

        # broadcast signature list
        while msg is not None:
            if len(msg) > SocketUtil.packet_size:
                sock.sendto(msg[:SocketUtil.packet_size], ('<broadcast>', port))
                msg = msg[SocketUtil.packet_size:]
            else:
                sock.sendto(msg, ('<broadcast>', port))
                msg = None

    @staticmethod
    def recv_msg(sock):
        raw_msg_len = SocketUtil.recvall(sock, 4)

        if not raw_msg_len:
            return None

        msg_len = struct.unpack('>I', raw_msg_len)[0]

        return SocketUtil.recvall(sock, msg_len)

    @staticmethod
    def recvall(sock, n):
        data = bytearray()

        while len(data) < n:
            buffer = sock.recv(n - len(data))

            if not buffer:
                return None

            data.extend(buffer)

        return bytes(data)

    @staticmethod
    def recv_broadcast(sock):
        # receive the packet size
        n = pickle.loads(sock.recv(1024))

        # receive data from the server
        return SocketUtil.recvall(sock, n)


class SS:
    """Shamir's t-out-of-n Secret Sharing.
    """

    @staticmethod
    def share(secret: object, t: int, n: int) -> list:
        """Generates a set of shares.

        Args:
            secret (object): the secret to be split.
            t (int): the threshold of being able to reconstruct the secret.
            n (int): the number of the shares.

        Returns:
            list: a set of shares.
        """

        secret_bytes = pickle.dumps(secret)

        # convert bytes to hex
        secret_hex = secret_bytes.hex()

        shares = SecretSharer.split_secret(secret_hex, t, n)

        return shares

    @staticmethod
    def recon(shares: list):
        secret_hex = SecretSharer.recover_secret(shares)

        # convert hex to bytes
        secret_bytes = bytes.fromhex(secret_hex)

        secret = pickle.loads(secret_bytes)

        return secret
