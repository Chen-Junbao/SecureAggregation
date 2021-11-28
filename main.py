import sys
import time
import pickle
import logging
import argparse
import threading

from utils import SIG
from entities.user import User
from entities.server import Server, SignatureRequestHandler

entities = {}       # the dict storing all users and the server


def init(user_ids: list) -> dict:
    """Generate all users and the server, and generates RSA keys for signature.

    Args:
        user_ids (list): the ids of all users.
    """

    entities["server"] = Server()
    SignatureRequestHandler.user_num = len(user_ids)

    # start the server
    server_thread = threading.Thread(
        target=entities["server"].tcp_server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    pub_key_map = {}    # the dict storing all users' public keys

    for id in user_ids:
        pub_key, priv_key = SIG.gen(nbits=1024)
        pub_key_map[id] = pub_key
        entities[id] = User(id, pub_key, priv_key)

    for id in user_ids:
        entities[id].pub_key_map = pub_key_map


def advertise_keys(user_ids: list) -> bool:
    """Each user generates two key pairs (c & s) and corresposneding signatures, then sends them to the server. The server collects all users' key pairs and then broadcasts them to all users.

    Args:
        user_ids (list): all users' ids.

    Returns:
        bool: If the server collects at least t messages from individual users, returns True. Otherwise, returns False.
    """
    user_num = len(user_ids)

    for id in user_ids:
        user = entities[id]

        # generate DH key pairs
        user.gen_DH_pairs()

        signature = user.gen_signature()

        data = pickle.dumps({
            "id": user.id,
            "c_pk": user.c_pk,
            "s_pk": user.s_pk,
            "signature": signature
        })

        # send c_pk, s_pk and the corresponding signature
        user.send(data, entities["server"].host, entities["server"].port)

        # listen the broadcast from the server
        thread = threading.Thread(target=user.listen_broadcast, args=[20000])
        thread.daemon = True
        thread.start()

    time.sleep(0.2)

    logging.info("all users have sent their signatures")

    t = 0.8 * user_num     # threshold value for SecretSharing

    wait_time = 10
    while len(SignatureRequestHandler.signature_list) != user_num and wait_time > 0:
        time.sleep(1)
        wait_time -= 1

    if len(SignatureRequestHandler.signature_list) >= t:
        entities["server"].broadcast_signatures(20000)

        return True
    else:
        # the number of the received messages is less than the threshold value for SecretSharing, abort
        return False


if __name__ == "__main__":
    # parse args
    parser = argparse.ArgumentParser(
        description="Initialize one round of federated learning.")
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
