#!/bin/sh
nohup ./tendermint start --proxy_app=evmstore --rpc.grpc_laddr=tcp://0.0.0.0:9091 > tendermint.log 2>&1 &
echo 'start success'