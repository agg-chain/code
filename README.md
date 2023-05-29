# AGG Chain

- Tendermint version: v0.34.24
- Ethereum version: v1.12.0

## Tips:

1. The main token is `AGG`
2. Support EIP1559
3. Does not support nonce reuse
4. Support gas, gasprice

## Single Test

### EVM

```shell
tendermint init
```

```shell
tendermint start --proxy_app=evmstore --rpc.grpc_laddr=tcp://0.0.0.0:9091
```
