#! /bin/bash

. scripts/utils.sh

function clean() {
    # remove all related containers and sa network
    if [[ $(docker ps -aq --filter ancestor=sa/user:1.0) ]]; then
        infoln "Removing user containers"
        docker stop $(docker ps -aq --filter ancestor=sa/user:1.0) >/dev/null
        docker rm $(docker ps -aq --filter ancestor=sa/user:1.0)
    fi
    if [[ $(docker ps -aq --filter ancestor=sa/server:1.0) ]]; then
        infoln "Removing server container"
        docker stop $(docker ps -aq --filter ancestor=sa/server:1.0) >/dev/null
        docker rm $(docker ps -aq --filter ancestor=sa/server:1.0)
    fi
    if [[ $(docker ps -aq --filter ancestor=sa/ta:1.0) ]]; then
        infoln "Removing ta container"
        docker stop $(docker ps -aq --filter ancestor=sa/ta:1.0) >/dev/null
        docker rm $(docker ps -aq --filter ancestor=sa/ta:1.0)
    fi
    if [[ $(docker network ls -q --filter name=sa) ]]; then
        infoln "Removing sa network"
        docker network rm sa
    fi
}

# parse command-line args
if [[ $# -lt 1 ]]; then
    printHelp
    exit 0
else
    while [[ $# -ge 1 ]]; do
        key="$1"
        case $key in
        -h)
            printHelp
            exit 0
            ;;
        -u)
            USER_NUM=$2
            shift
            ;;
        -t)
            WAIT_TIME=$2
            shift
            ;;
        *)
            errorln "Unknown flag: $key"
            printHelp
            exit 1
            ;;
        esac
        shift
    done
fi

user_ids=$(seq 1 $USER_NUM)                       # all users' ids
t=$(awk "BEGIN {printf \"%d\", $USER_NUM * 0.8}") # threshold value of Shamir's t-out-of-n Secret Sharing

clean

# create sa network and containers
docker network create sa
successln "Successfully created sa network"
infoln "Creating TA"
docker run -d --name ta -h ta --network sa sa/ta:1.0 python -u main.py $USER_NUM
successln "Successfully created TA"
sleep 10
infoln "Creating server"
docker run -d --name server -h server --network sa sa/server:1.0 $USER_NUM $t $WAIT_TIME
successln "Successfully created server"
sleep 5
infoln "Creating $USER_NUM users"
for i in $user_ids; do
    docker run -d --gpus all --name user"$i" -h user"$i" --network sa sa/user:1.0 python -u main.py $i $t
done
successln "Successfully created $USER_NUM users"
