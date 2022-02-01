import os
import sys
import rsa
import pickle
import socket
import multiprocessing
import numpy as np
import tensorflow as tf

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
    pub_key_map = {}    # the dict storing all users' public keys
    priv_key_map = {}    # the dict storing all users' private keys

    for id in user_ids:
        pub_key, priv_key = SIG.gen(nbits=1024)
        pub_key_map[id] = pub_key
        priv_key_map[id] = priv_key

    return pub_key_map, priv_key_map


def generate_dataset(shape=(784,)) -> dict:
    """Generate dataset for each user.

    Args:
        shape (tuple): the sample shape (for MNIST, it can be (784,) or (28, 28, 1)).

    Returns:
        dataset (dict): all users' datasets and validation dataset.
    """

    clients_num = len(user_ids)
    mnist = tf.keras.datasets.mnist

    (x_train, y_train), (x_test, y_test) = mnist.load_data(path="mnist.npz")
    x_train = (x_train / 255).reshape((-1, *shape))
    x_test = (x_test / 255).reshape((-1, *shape))
    x_train = x_train.astype(np.float32)
    x_test = x_test.astype(np.float32)

    dataset = {}
    dataset_size = len(y_train)
    client_dataset_size = dataset_size // clients_num

    for i in range(clients_num - 1):
        data = {'x': x_train[i * client_dataset_size: (i + 1) * client_dataset_size],
                'y': y_train[i * client_dataset_size: (i + 1) * client_dataset_size]}
        dataset[user_ids[i]] = data
    data = {'x': x_train[(clients_num - 1) * client_dataset_size:],
            'y': y_train[(clients_num - 1) * client_dataset_size:]}
    dataset[user_ids[-1]] = data

    dataset["server"] = {'x': x_test, 'y': y_test}

    return dataset


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


@app.route("/getDataset")
def get_model():
    host = socket.gethostbyaddr(request.remote_addr)[0].split('.')[0]
    if host != "server":
        id = host[4:]
    else:
        id = host

    data = dataset[id]

    return pickle.dumps(data)


if __name__ == "__main__":
    user_ids = [str(id) for id in range(1, int(sys.argv[1]) + 1)]
    model_name = sys.argv[2]

    if model_name == "CNN":
        dataset = generate_dataset((28, 28, 1))
    else:
        dataset = generate_dataset()

    pub_key_map, priv_key_map = generate_keys()

    app.run(host="0.0.0.0")
