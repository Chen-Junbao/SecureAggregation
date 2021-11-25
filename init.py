import os
import shutil
import time
import threading
import argparse

from utils import *


def TA_init(user_ids: list, key_root: str):
    """Generates keys for all users.

    Args:
        user_ids (list): the ids of all users.
        key_root (str): the root path where to save all keys.
    """
    if os.path.exists(key_root):
        shutil.rmtree(key_root)

    def generate_keys(key_root, id):
        SIG.gen(path=os.path.join(key_root, "rsa", str(id)))
        AE.gen(path=os.path.join(key_root, "aes", str(id)))
        KA.gen(path=os.path.join(key_root, "dh", str(id)))

    for id in user_ids:
        threading.Thread(target=generate_keys, args=(key_root, id)).start()


if __name__ == "__main__":
    # parse args
    parser = argparse.ArgumentParser(
        description="Initialize one round of federated learning.")
    parser.add_argument("-u", "--user", metavar='user_number', type=int,
                        default=100, help="the number of users")
    parser.add_argument("-k", "--key", metavar="key_path", type=str,
                        default="./keys", help="the root path where to save all keys.")

    args = parser.parse_args()

    start = time.time()
    TA_init([id for id in range(1, args.user + 1)], args.key)
    end = time.time()
    print(end - start)
