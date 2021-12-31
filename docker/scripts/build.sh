#! /bin/bash

. scripts/utils.sh

infoln "Building docker images for each entity"
docker build -t sa/server:1.0 ./server
docker build -t sa/ta:1.0 ./ta
docker build -t sa/user:1.0 ./user
successln "Successfully built server, TA and user images"
