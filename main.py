import sys
import time
import pickle
import random
import logging
import argparse

from tqdm import tqdm
from threading import Thread
from utils import *
from entities.user import User
from entities.server import *

entities = {}       # the dict storing all users and the server
t = 0               # threshold value of Shamir's t-out-of-n Secret Sharing
U_1 = []            # ids of all online users
U_2 = []            # ids of all users sending the ciphertexts


def init(user_ids: list) -> dict:
    """Generate all users and the server, and generates RSA keys for signature.

    Args:
        user_ids (list): the ids of all users.
    """

    entities["server"] = Server()
    SignatureRequestHandler.user_num = len(user_ids)

    # start the signature socket server
    server_thread = Thread(target=entities["server"].signature_server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    pub_key_map = {}    # the dict storing all users' public keys

    with tqdm(total=len(user_ids), desc='Generating keys', unit_scale=True, unit='') as bar:
        for id in user_ids:
            pub_key, priv_key = SIG.gen(nbits=1024)
            pub_key_map[id] = pub_key
            entities[id] = User(id, pub_key, priv_key)

            bar.update(1)

    for id in user_ids:
        entities[id].pub_key_map = pub_key_map

    global t
    t = int(0.8 * len(user_ids))


def advertise_keys(user_ids: list) -> bool:
    """Each user generates two key pairs (c & s) and corresposneding signatures, then sends them to the server.
       The server collects all users' key pairs and then broadcasts them to all users.

    Args:
        user_ids (list): all users' ids.

    Returns:
        bool: If the server collects at least t messages from individual users, returns True. Otherwise, returns False.
    """
    user_num = len(user_ids)
    server = entities["server"]

    for id in user_ids:
        user = entities[id]

        # generate DH key pairs
        user.gen_DH_pairs()

        signature = user.gen_signature()

        msg = pickle.dumps({
            "id": user.id,
            "c_pk": user.c_pk,
            "s_pk": user.s_pk,
            "signature": signature
        })

        # send c_pk, s_pk and the corresponding signature
        user.send(msg, server.host, server.signature_port)

        # listen the broadcast from the server
        thread = Thread(target=user.listen_broadcast, args=[server.broadcast_port])
        thread.daemon = True
        thread.start()

    time.sleep(0.2)

    wait_time = 10
    while len(SignatureRequestHandler.U_1) != user_num and wait_time > 0:
        time.sleep(1)
        wait_time -= 1

    if len(SignatureRequestHandler.U_1) >= t:
        global U_1
        U_1 = server.broadcast_signatures(server.broadcast_port)

        logging.info("{} users have sent signatures".format(len(U_1)))

        return True
    else:
        # the number of the received messages is less than the threshold value for SecretSharing, abort
        return False


def share_keys() -> bool:
    # all online users verify the signatures
    server = entities["server"]
    SecretShareRequestHandler.U_1_num = len(U_1)

    # start the secret sharing socket server
    server_thread = Thread(target=server.ss_server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    for u in U_1:
        user = entities[u]

        if not user.ver_signature():
            sys.exit(1)

        user.gen_shares(U_1, t, server.host, server.ss_port)

    time.sleep(0.2)

    wait_time = 10
    while len(SecretShareRequestHandler.U_2) != len(U_1) and wait_time > 0:
        time.sleep(1)
        wait_time -= 1

    if len(SecretShareRequestHandler.U_2) >= t:
        logging.info("{} users have sent ciphertexts".format(len(SecretShareRequestHandler.U_2)))

        return True
    else:
        # the number of the received messages is less than the threshold value for SecretSharing, abort
        return False


if __name__ == "__main__":
    # parse args
    parser = argparse.ArgumentParser(description="Initialize one round of federated learning.")
    parser.add_argument("-u", "--user", metavar='user_number', type=int,
                        default=10, help="the number of users")
    parser.add_argument("-k", "--key", metavar="key_path", type=str,
                        default="./keys", help="the root path where to save all keys.")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(module)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

    user_ids = [str(id) for id in range(1, args.user + 1)]

    init(user_ids)

    print("{:=^80s}".format("Finish Initializing"))

    res = advertise_keys(user_ids)

    if not res:
        logging.error("insufficient messages received by the server!")

        sys.exit(1)

    time.sleep(1)

    print("{:=^80s}".format("Finish Advertising keys"))

    logging.info("online users: " + ','.join(U_1))

    share_keys()
