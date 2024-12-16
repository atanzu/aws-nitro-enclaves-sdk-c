#!/bin/bash

set -e

docker build --target kmstool-enclave-cli-go -t kmstool-enclave-cli-go -f ../../containers/Dockerfile.al2 ../..
CONTAINER_ID=$(docker create kmstool-enclave-cli-go)
docker cp $CONTAINER_ID:/kmstool_enclave_cli_go ./
docker cp $CONTAINER_ID:/usr/lib64/libnsm.so ./
docker rm $CONTAINER_ID
