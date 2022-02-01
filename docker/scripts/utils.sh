#!/bin/bash

C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_BLUE='\033[0;34m'

function printHelp() {
  cat <<EOF
Usage:  start.sh [OPTIONS] [ARG...]

Secure aggregation protocol for federated learning

Option:
  -h, --help            Show this help message and exit
  -u, --user int        Set the number of users
  -t, --wait int        Set maximum waiting time for each round
  -i, --iteration int   Set the iteration of federated learning
  --model str           Set the trained model (MLP or CNN)
  --batchsize int       Set the training batch size

Examples:
  start.sh -u 500 -t 300 -i 20 --model CNN --batchsize 28
EOF
}

# println echos string
function println() {
  echo -e "$1"
}

# errorln echos i red color
function errorln() {
  println "${C_RED}${1}${C_RESET}"
}

# successln echos in green color
function successln() {
  println "${C_GREEN}${1}${C_RESET}"
}

# infoln echos in blue color
function infoln() {
  println "${C_BLUE}${1}${C_RESET}"
}

export -f errorln
export -f successln
export -f infoln
