import os
import sys
import pickle
import logging
import requests
import numpy as np
import tensorflow as tf

from user import User
from tensorflow.keras.initializers import RandomNormal

os.environ["CUDA_VISIBLE_DEVICES"] = "-1"


def create_model(name):
    if name == "MLP":
        return tf.keras.models.Sequential([
            tf.keras.layers.InputLayer(input_shape=(784,)),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dense(10),
            tf.keras.layers.Softmax()
        ])
    elif name == "CNN":
        return tf.keras.models.Sequential([
            tf.keras.layers.Conv2D(32, (3, 3), activation='relu', kernel_initializer=RandomNormal(),
                                   input_shape=(28, 28, 1)),
            tf.keras.layers.Conv2D(64, (3, 3), activation='relu', kernel_initializer=RandomNormal()),
            tf.keras.layers.MaxPooling2D(pool_size=(2, 2)),
            tf.keras.layers.Dropout(0.25),
            tf.keras.layers.Flatten(),
            tf.keras.layers.Dense(128, activation='relu', kernel_initializer=RandomNormal()),
            tf.keras.layers.Dropout(0.5),
            tf.keras.layers.Dense(10, activation='softmax', kernel_initializer=RandomNormal())
        ])
    else:
        raise Exception("Invalid model name!")


def advertise_keys(user):
    user.gen_DH_pairs()

    signature = user.gen_signature()

    msg = pickle.dumps({
        "id": user.id,
        "c_pk": user.c_pk,
        "s_pk": user.s_pk,
        "signature": signature
    })

    # send c_pk, s_pk and the corresponding signature
    user.send(msg, "server", 20000)

    # listen the broadcast from the server
    user.listen_broadcast(10000)


def share_keys(user, t):
    if not user.ver_signature():
        sys.exit(1)

    user.gen_shares(user.U_1, t, "server", 20001)

    user.listen_ciphertexts()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

    id = sys.argv[1]
    t = int(sys.argv[2])
    iteration = int(sys.argv[3])
    model_name = sys.argv[4]
    batch_size = int(sys.argv[5])

    # get training dataset
    dataset_url = "http://ta:5000/getDataset"
    req = requests.get(dataset_url)
    dataset = pickle.loads(req.content)

    # get public key map and own private key from TA
    key_url = "http://ta:5000/getKey"
    req = requests.get(key_url)
    data = pickle.loads(req.content)

    user = User(id, data["pubKeyMap"][id], data["privKey"])
    user.pub_key_map = data["pubKeyMap"]

    user_ids = user.pub_key_map.keys()

    model = create_model(model_name)
    optimizer = tf.keras.optimizers.Adam(learning_rate=1e-3)
    model.compile(optimizer, loss='sparse_categorical_crossentropy', metrics='sparse_categorical_accuracy')

    # train locally
    for i in range(iteration):
        # receive global weights
        global_weights = user.listen_global_weights()
        model.set_weights(global_weights)

        model.fit(dataset['x'], dataset['y'], batch_size=batch_size, epochs=20)

        gradients = model.get_weights()

        advertise_keys(user)

        share_keys(user, t)

        user.mask_gradients(gradients, "server", 20002)

        user.consistency_check("server", 20003)

        user.unmask_gradients("server", 20004)
