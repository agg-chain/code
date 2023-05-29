package psql

import (
	"github.com/agg-chain/aggchain/state/indexer"
	"github.com/agg-chain/aggchain/state/txindex"
)

var (
	_ indexer.BlockIndexer = BackportBlockIndexer{}
	_ txindex.TxIndexer    = BackportTxIndexer{}
)
