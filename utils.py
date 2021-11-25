import os
import rsa
import multiprocessing

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from diffiehellman import DiffieHellman


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

        pub_key, priv_key = rsa.newkeys(
            nbits, poolsize=multiprocessing.cpu_count())

        if path is not None:
            os.makedirs(path)

            # save the pub_key and priv_key
            with open(os.path.join(path, "pub.pem"), 'wb') as f:
                f.write(pub_key.save_pkcs1())
            with open(os.path.join(path, "priv.pem"), 'wb') as f:
                f.write(priv_key.save_pkcs1())

        return pub_key, priv_key

    @staticmethod
    def sign(message: bytes, priv_key, hash_method="SHA-1"):
        return rsa.sign(message, priv_key, hash_method)

    @staticmethod
    def verify(message: bytes, signature: bytes, pub_key) -> bool:
        try:
            rsa.verify(message, signature, pub_key)

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
    def gen(path: str = None) -> tuple:
        """Generates public and private keys, and saves them.

        Args:
            path (str): path to store public and private keys.

        Returns:
            Tuple[PublicKey, PrivateKey]: the public and private keys.
        """

        dh = DiffieHellman()
        pub_key, priv_key = dh.get_public_key(), dh.get_private_key()

        if path is not None:
            os.makedirs(path)

            # save the pub_key and priv_key
            with open(os.path.join(path, "pub"), 'wb') as f:
                f.write(pub_key)
            with open(os.path.join(path, "priv"), 'wb') as f:
                f.write(priv_key)

        return pub_key, priv_key

    @staticmethod
    def agree(priv_key: bytes, pub_key: bytes) -> bytes:
        """Generates the shared key between two users.

        Args:
            priv_key (bytes): the private key of one user.
            pub_key (bytes): the public key of the other user.

        Returns:
            bytes: the shared key between the two users.
        """
        dh = DiffieHellman()

        dh.set_private_key(priv_key)
        shared_key = dh.generate_shared_key(pub_key)

        return shared_key
