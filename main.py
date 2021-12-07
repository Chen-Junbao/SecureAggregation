import sys
import time
import pickle
import logging
import argparse

import numpy as np

from tqdm import tqdm
from threading import Thread
from utils import *
from entities.user import User
from entities.server import *

entities = {}       # the dict storing all users and the server
t = 0               # threshold value of Shamir's t-out-of-n Secret Sharing
U_1 = []            # ids of all online users
U_2 = []            # ids of all users sending the ciphertexts
U_3 = []            # ids of all users sending the masked gradients
U_4 = []            # ids of all users sending the consistency check


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

    def fun(user):
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

    for id in user_ids:
        user = entities[id]

        thread = Thread(target=fun, args=[user])
        thread.daemon = True
        thread.start()

    time.sleep(0.2)

    wait_time = 10
    while len(SignatureRequestHandler.U_1) != user_num and wait_time > 0:
        time.sleep(1)
        wait_time -= 1

    if len(SignatureRequestHandler.U_1) >= t:
        global U_1
        U_1 = SignatureRequestHandler.U_1

        logging.info("{} users have sent signatures".format(len(U_1)))

        server.broadcast_signatures(server.broadcast_port)

        return True
    else:
        # the number of the received messages is less than the threshold value for SecretSharing, abort
        return False


def share_keys() -> bool:
    """Each user shares s_sk and random_seed, then encrypts them and sends these ciphertexts to the server.
       The server collects all users' ciphertexts and then sends them to the users in U_2.

    Returns:
        bool: If the server collects at least t messages from individual users, returns True. Otherwise, returns False.
    """

    # all online users verify the signatures
    server = entities["server"]
    SecretShareRequestHandler.U_1_num = len(U_1)

    # start the secret sharing socket server
    server_thread = Thread(target=server.ss_server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    def fun(user):
        if not user.ver_signature():
            sys.exit(1)

        user.gen_shares(U_1, t, server.host, server.ss_port)

        # listen shares from the server
        thread = Thread(target=user.listen_ciphertexts)
        thread.daemon = True
        thread.start()

    for u in U_1:
        user = entities[u]

        thread = Thread(target=fun, args=[user])
        thread.daemon = True
        thread.start()

    time.sleep(0.2)

    wait_time = 10
    while len(SecretShareRequestHandler.U_2) != len(U_1) and wait_time > 0:
        time.sleep(1)
        wait_time -= 1

    if len(SecretShareRequestHandler.U_2) >= t:
        global U_2
        U_2 = SecretShareRequestHandler.U_2

        logging.info("{} users have sent ciphertexts".format(len(U_2)))

        for u in U_2:
            msg = pickle.dumps(SecretShareRequestHandler.ciphertexts_map[u])
            server.send(msg, entities[u].host, entities[u].port)

        return True
    else:
        # the number of the received messages is less than the threshold value for SecretSharing, abort
        return False


def masked_input_collection() -> bool:
    """Each user masks its gradients by adding random vectors generated by a PRG, then sends them to the server.
       The server colects all users' masked inputs and then sends these users' id to each user.

    Returns:
        bool: If the server collects at least t messages from individual users, returns True. Otherwise, returns False.
    """

    server = entities["server"]
    MaskedGradientsRequestHandler.U_2_num = len(U_2)

    # start the masked gradients collection socket server
    server_thread = Thread(target=server.masked_gradients_server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    def fun(user):
        gradients = np.random.random((2, 2))
        user.mask_gradients(U_2, gradients, server.host, server.masked_gradients_port)

    for u in U_2:
        user = entities[u]

        thread = Thread(target=fun, args=[user])
        thread.daemon = True
        thread.start()

    time.sleep(0.2)

    wait_time = 10
    while len(MaskedGradientsRequestHandler.U_3) != len(U_2) and wait_time > 0:
        time.sleep(1)
        wait_time -= 1

    if len(MaskedGradientsRequestHandler.U_3) >= t:
        global U_3
        U_3 = MaskedGradientsRequestHandler.U_3

        logging.info("{} users have sent masked gradients".format(len(U_3)))

        return True
    else:
        # the number of the received messages is less than the threshold value for SecretSharing, abort
        return False


def consistency_check() -> int:
    server = entities["server"]
    ConsistencyCheckRequestHandler.U_3_num = len(U_3)

    # start the consistency check socket server
    server_thread = Thread(target=server.consistency_check_server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    status_list = []

    for u in U_3:
        thread = Thread(target=entities[u].consistency_check, args=[server.host, server.consistency_check_port, status_list])
        thread.daemon = True
        thread.start()

    msg = pickle.dumps(U_3)
    for u in U_3:
        server.send(msg, entities[u].host, entities[u].port)
    
    time.sleep(0.2)

    wait_time = 10
    while len(ConsistencyCheckRequestHandler.U_4) != len(U_3) and wait_time > 0:
        time.sleep(1)
        wait_time -= 1

    if len(ConsistencyCheckRequestHandler.U_4) >= t:
        global U_4
        U_4 = ConsistencyCheckRequestHandler.U_4

        logging.info("{} users have sent consistency checks".format(len(U_4)))

        for u in U_4:
            msg = pickle.dumps(ConsistencyCheckRequestHandler.consistency_check_map)
            server.send(msg, entities[u].host, entities[u].port)
        
        if False in status_list:
            # at least one user failed in consistency check
            return 2
        else:
            return 0
    else:
        # the number of the received messages is less than the threshold value for SecretSharing, abort
        return 1


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

    print("{:=^80s}".format("Finish Advertising Keys"))

    logging.info("online users: " + ','.join(U_1))

    res = share_keys()
    if not res:
        logging.error("insufficient ciphertexts received by the server!")

        sys.exit(1)

    time.sleep(1)

    print("{:=^80s}".format("Finish Sharing Keys"))

    res = masked_input_collection()
    if not res:
        logging.error("insufficient masked gradients received by the server!")

        sys.exit(1)

    time.sleep(1)

    print("{:=^80s}".format("Finish Mask Input"))

    status_code = consistency_check()
    if status_code == 1:
        logging.error("insufficient consistency checks received by the server!")

        sys.exit(1)
    elif status_code == 2:
        logging.error("at least one user failed in consistency check!")

        sys.exit(2)
    
    print("{:=^80s}".format("Finish Consistency Check"))
