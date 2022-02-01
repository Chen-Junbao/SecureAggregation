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

USER_NUM=10
WAIT_TIME=100
ITERATION=10
MODEL="MLP"
BATCH_SIZE=28

# parse command-line args
if [[ $# -lt 1 ]]; then
    printHelp
    exit 0
else
    while [[ $# -ge 1 ]]; do
        key="$1"
        case $key in
        -h | --help)
            printHelp
            exit 0
            ;;
        -u | --user)
            USER_NUM=$2
            shift
            ;;
        -t | --wait)
            WAIT_TIME=$2
            shift
            ;;
        -i | --iteration)
            ITERATION=$2 # training iterations for federated learning
            shift
            ;;
        --model)
            MODEL=$2 # the name of the trained model

            if [[ $MODEL != "CNN" && $MODEL != "MLP" ]]; then
                errorln "Invalid model name, CNN or MLP are supported!"
                exit 1
            fi

            shift
            ;;
        --batchsize)
            BATCH_SIZE=$2
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
docker run -d --name ta -h ta --network sa sa/ta:1.0 python -u main.py $USER_NUM $MODEL
# wait for preparing dataset and keys
while [[ $(docker logs ta 2>&1 | grep "Running on" | wc -l) -eq 0 ]]; do
    sleep 1
done
successln "Successfully created TA"

infoln "Creating $USER_NUM users"
for i in $user_ids; do
    docker run -d --gpus all --name user"$i" -h user"$i" --network sa sa/user:1.0 python -u main.py $i $t $ITERATION $MODEL $BATCH_SIZE
done
successln "Successfully created $USER_NUM users"
infoln "Creating server"

docker run -d --name server -h server -v $PWD/server:/server --network sa sa/server:1.0 $USER_NUM $t $WAIT_TIME $ITERATION $MODEL
successln "Successfully created server"
sleep 5
