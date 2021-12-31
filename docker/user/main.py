import sys
import pickle
import logging
import requests
import numpy as np

from user import User


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


def masked_input_collection(user, shape=(2, 2)):
    gradients = np.random.random(shape)
    print(gradients)
    user.mask_gradients(gradients, "server", 20002)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

    id = sys.argv[1]
    t = int(sys.argv[2])

    # get public key map and own private key from TA
    url = "http://ta:5000/getKey"
    req = requests.get(url)
    data = pickle.loads(req.content)

    user = User(id, data["pubKeyMap"][id], data["privKey"])
    user.pub_key_map = data["pubKeyMap"]

    user_ids = user.pub_key_map.keys()

    advertise_keys(user)

    share_keys(user, t)

    masked_input_collection(user)

    user.consistency_check("server", 20003)

    user.unmask_gradients("server", 20004)
