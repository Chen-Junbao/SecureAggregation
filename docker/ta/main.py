import os
import sys
import rsa
import pickle
import socket
import multiprocessing

from flask import Flask, request


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


def generate_keys():
    user_ids = [str(id) for id in range(1, int(sys.argv[1]) + 1)]
    pub_key_map = {}    # the dict storing all users' public keys
    priv_key_map = {}    # the dict storing all users' private keys

    for id in user_ids:
        pub_key, priv_key = SIG.gen(nbits=1024)
        pub_key_map[id] = pub_key
        priv_key_map[id] = priv_key

    return pub_key_map, priv_key_map


pub_key_map, priv_key_map = generate_keys()

app = Flask(__name__)


@app.route("/getKey")
def get_pub_key():
    host = socket.gethostbyaddr(request.remote_addr)[0]
    id = host.split('.')[0][4:]

    data = {
        "pubKeyMap": pub_key_map,
        "privKey": priv_key_map[id]
    }

    return pickle.dumps(data)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
