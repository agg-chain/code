package evmstore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/agg-chain/aggchain/abci/example/code"
	"github.com/agg-chain/aggchain/abci/example/evmstore/database"
	"github.com/agg-chain/aggchain/abci/types"
	"github.com/agg-chain/aggchain/libs/log"
	"github.com/agg-chain/aggchain/version"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	evmtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/params"
	dbm "github.com/tendermint/tm-db"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	stateKey  = []byte("statekey0.1")
	evmTxsKey = []byte("evmtxskey0.1")

	ChainName = "AGG"
	ChainId   = big.NewInt(11000)

	LevelDBName = os.Getenv("LEVEL_DB_NAME")
	LevelDBDir  = ".leveldbdir"

	ProtocolVersion uint64 = 0x1
	err             error

	logger log.Logger

	ZeroAddress = "0x0000000000000000000000000000000000000000"

	// txSlotSize is used to calculate how many data slots a single transaction
	// takes up based on its size. The slots are used as DoS protection, ensuring
	// that validating a new transaction remains a constant operation (in reality
	// O(maxslots), where max slots are 4 currently).
	txSlotSize = 32 * 1024

	// txMaxSize is the maximum size a single transaction can have. This field has
	// non-trivial consequences: larger transactions are significantly harder and
	// more expensive to propagate; larger transactions also take more resources
	// to validate whether they fit into the pool or not.
	txMaxSize = 4 * txSlotSize // 128KB
)

type State struct {
	// tendermint state
	db      dbm.DB
	Size    int64  `json:"size"`
	Height  int64  `json:"height"`
	AppHash []byte `json:"app_hash"`

	// EVM state
	ethStateDb  state.Database
	nextTxNum   *big.Int
	evmStateDB  *state.StateDB
	signer      evmtypes.Signer
	chainConfig *params.ChainConfig
}

func init() {
	logger = log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	logger = logger.With("module", "evmstore")
}

func loadState(db dbm.DB) State {
	var _state State
	_state.db = db

	stateBytes, err := db.Get(stateKey)
	if err != nil {
		panic(err)
	}
	if len(stateBytes) != 0 {
		err = json.Unmarshal(stateBytes, &_state)
		if err != nil {
			panic(err)
		}
	}

	return _state
}

func saveState(state State) {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	err = state.db.Set(stateKey, stateBytes)
	state.Size++
	if err != nil {
		panic(err)
	}
}

//---------------------------------------------------

var _ types.Application = (*EVMApplication)(nil)

type EVMApplication struct {
	types.BaseApplication

	state        State
	RetainBlocks int64 // blocks to retain after commit (via ResponseCommit.RetainHeight)
}

func NewApplication() *EVMApplication {
	db, err := dbm.NewGoLevelDB(LevelDBName, LevelDBDir)
	if err != nil {
		panic(err)
	}

	s := loadState(db)
	app := &EVMApplication{state: s}
	app.recoverEVMStateDB()
	return app
}

func (app *EVMApplication) Info(req types.RequestInfo) (resInfo types.ResponseInfo) {
	return types.ResponseInfo{
		Data:             fmt.Sprintf("{\"chain-name\":%v}", ChainName),
		Version:          version.ABCIVersion,
		AppVersion:       ProtocolVersion,
		LastBlockHeight:  app.state.Height,
		LastBlockAppHash: app.state.AppHash,
	}
}

func (app *EVMApplication) DeliverTx(req types.RequestDeliverTx) types.ResponseDeliverTx {
	if len(string(req.Tx)) < 2 {
		msg := fmt.Sprintf("executeEvmTx error. Tx error: %s", string(req.Tx))
		logger.Error(msg)
		return types.ResponseDeliverTx{Code: code.CodeTypeUnknownError, Info: msg}
	}

	txInAgg, err := convertReqTx2EvmTx(req.Tx)
	if err != nil {
		msg := fmt.Sprintf("convertReqTx2EvmTx error: %s", err.Error())
		logger.Error(msg)
		return types.ResponseDeliverTx{Code: code.CodeTypeUnknownError, Info: msg}
	}
	result, err := app.executeEvmTx(txInAgg)
	if err != nil {
		msg := fmt.Sprintf("executeEvmTx error: %s", err.Error())
		logger.Error(msg)
		return types.ResponseDeliverTx{Code: code.CodeTypeUnknownError, Info: msg}
	}
	err = app.saveEVMState(req.Tx)
	if err != nil {
		msg := fmt.Sprintf("saveEVMState error: %s", err.Error())
		logger.Error(msg)
		return types.ResponseDeliverTx{Code: code.CodeTypeUnknownError, Info: msg}
	}

	events := []types.Event{
		{
			Type: "app",
			Attributes: []types.EventAttribute{
				{Key: []byte("creator"), Value: []byte("EVM"), Index: true},
				{Key: []byte("key"), Value: req.Tx, Index: true},
				{Key: []byte("index_key"), Value: []byte("index is working"), Index: true},
				{Key: []byte("noindex_key"), Value: []byte("index is working"), Index: false},
			},
		},
	}

	return types.ResponseDeliverTx{Code: code.CodeTypeOK, Events: events, Data: result}
}

func convertReqTx2EvmTx(tx []byte) (*evmtypes.Transaction, error) {
	txInAgg := &evmtypes.Transaction{}
	rawTxBytes, err := hex.DecodeString(string(tx)[2:])
	if err != nil {
		msg := fmt.Sprintf("decodeString error: %s", err.Error())
		logger.Error(msg)
		return txInAgg, err
	}
	err = txInAgg.UnmarshalBinary(rawTxBytes)
	return txInAgg, err
}

func convertReqTx2EvmCallMsg(tx []byte) (*ethereum.CallMsg, error) {
	callMsg := &ethereum.CallMsg{}
	rawTxBytes, err := hex.DecodeString(string(tx)[2:])
	if err != nil {
		msg := fmt.Sprintf("decodeString error: %s", err.Error())
		logger.Error(msg)
		return callMsg, err
	}
	err = json.Unmarshal(rawTxBytes, &callMsg)
	return callMsg, err
}

func (app *EVMApplication) saveEVMState(tx []byte) error {
	logger.Debug("saveEVMState")
	key := append(evmTxsKey, []byte(strconv.FormatInt(time.Now().UnixNano(), 10))...)
	err = app.state.db.Set(key, tx)
	app.state.Size++
	if err != nil {
		return err
	}
	app.state.nextTxNum = app.state.nextTxNum.Add(app.state.nextTxNum, big.NewInt(1))
	return nil
}

func (app *EVMApplication) CheckTx(req types.RequestCheckTx) types.ResponseCheckTx {
	txDataHex := string(req.Tx)
	logger.Debug(fmt.Sprintf("check evm tx. Tx data: %s", txDataHex))

	if len(txDataHex) < 2 {
		logger.Error(fmt.Sprintf("txDataHex length less 2. txDataHex: %s", err.Error()))
		return types.ResponseCheckTx{Code: code.CodeTypeEncodingError, GasWanted: 1, Info: "txDataHex length error"}
	}

	txInAgg := &evmtypes.Transaction{}
	rawTxBytes, err := hex.DecodeString(txDataHex[2:])
	if err != nil {
		logger.Error(fmt.Sprintf("DecodeString hex tx error: %s", err.Error()))
		return types.ResponseCheckTx{Code: code.CodeTypeEncodingError, GasWanted: 1, Info: "decodeString error"}
	}
	err = txInAgg.UnmarshalBinary(rawTxBytes)
	if err != nil {
		logger.Error(fmt.Sprintf("UnmarshalBinary tx error: %s", err.Error()))
		return types.ResponseCheckTx{Code: code.CodeTypeEncodingError, GasWanted: 1, Info: "unmarshalBinary error"}
	}

	// verify tx
	err = app.verifyEvmTx(txInAgg)
	if err != nil {
		logger.Error(fmt.Sprintf("verifyEvmTx error: %s", err.Error()))
		return types.ResponseCheckTx{Code: code.CodeTypeEncodingError, GasWanted: 1, Info: "verifyEvmTx error: " + err.Error()}
	}

	return types.ResponseCheckTx{Code: code.CodeTypeOK, GasWanted: 1}
}

func (app *EVMApplication) Commit() types.ResponseCommit {
	// Using a memdb - just return the big endian size of the db
	appHash := make([]byte, 8)
	binary.PutVarint(appHash, app.state.Size)
	app.state.AppHash = appHash
	app.state.Height++
	saveState(app.state)

	resp := types.ResponseCommit{Data: appHash}
	if app.RetainBlocks > 0 && app.state.Height >= app.RetainBlocks {
		resp.RetainHeight = app.state.Height - app.RetainBlocks + 1
	}
	return resp
}

// Query Returns an associated value or nil if missing.
func (app *EVMApplication) Query(reqQuery types.RequestQuery) (resQuery types.ResponseQuery) {
	var value []byte
	resQuery.Key = reqQuery.Data
	parts := bytes.Split(resQuery.Key, []byte("="))
	key, value := parts[0], parts[1]
	if string(key) == "get_balance" {
		logger.Debug("get_balance")
		address := common.Address{}
		addressBytes, err := hexutil.Decode(string(value))
		if err != nil {
			panic(err)
		}
		address.SetBytes(addressBytes)
		balance := app.state.evmStateDB.GetBalance(address)
		value = []byte((*hexutil.Big)(balance).String())
	} else if string(key) == "get_nonce" {
		logger.Debug("get_nonce")
		address := common.Address{}
		addressBytes, err := hexutil.Decode(string(value))
		if err != nil {
			panic(err)
		}
		address.SetBytes(addressBytes)
		nonce := app.state.evmStateDB.GetNonce(address)
		value = []byte(strconv.FormatUint(nonce, 16))
	} else if string(key) == "get_tx" {
		logger.Debug("get_tx")
		vs := strings.Split(string(value), "_")
		start, _ := strconv.Atoi(vs[1])
		end, _ := strconv.Atoi(vs[2])
		txs, err := database.QueryRelationTxDetails(vs[0], vs[0], uint64(start), uint64(end))
		if err != nil {
			panic(err)
		}
		value, err = json.Marshal(txs)
		if err != nil {
			panic(err)
		}
	} else if string(key) == "eth_call" {
		// 调用合约
		logger.Debug("eth_call")
		txInAgg, err := convertReqTx2EvmCallMsg(value)
		if err != nil {
			msg := fmt.Sprintf("convertReqTx2EvmTx error: %s", err.Error())
			logger.Error(msg)
			resQuery.Log = msg
		} else {
			result, err := app.executeContractTx(app.state.evmStateDB, txInAgg)
			if err != nil {
				msg := fmt.Sprintf("Contract call error: %s", err.Error())
				logger.Error(msg)
				resQuery.Log = msg
			}
			value = result
		}
	}

	if value != nil {
		resQuery.Log = "exists"
	}
	resQuery.Value = value
	resQuery.Height = app.state.Height

	return resQuery
}

func (app *EVMApplication) executeEvmTx(txInAgg *evmtypes.Transaction) ([]byte, error) {
	txBytes, _ := txInAgg.MarshalJSON()
	logger.Debug(fmt.Sprintf("execute evm tx. Tx data: %s", string(txBytes)))

	// save nonce
	fromAddress, _ := evmtypes.Sender(app.state.signer, txInAgg)
	app.state.evmStateDB.SetNonce(fromAddress, app.state.evmStateDB.GetNonce(fromAddress)+1)

	// save to db
	txDB := &database.TxDetailsInfo{
		TxHeight: int32(app.state.Height + 1),
		TxHash:   txInAgg.Hash().Hex(),
		TxFrom:   fromAddress.Hex(),
		TxTo:     txInAgg.To().Hex(),
		TxValue:  txInAgg.Value().String(),
		RawData:  string(txBytes),
	}

	// execute evm tx
	_code := app.state.evmStateDB.GetCode(*txInAgg.To())
	if len(_code) == 0 {
		// 非合约调用
		if len(txInAgg.Data()) == 0 {
			// 处理主代币
			logger.Debug("Main token tx")
			err = app.handleMainTokenTx(app.state.evmStateDB, txInAgg)
			if err != nil {
				return nil, err
			}
			logger.Debug("tx hash: " + txInAgg.Hash().Hex())
			err = database.InsertTxDetails(txDB)
			if err != nil {
				return nil, err
			}
			return txInAgg.Hash().Bytes(), nil
		} else if txInAgg.To().String() == ZeroAddress {
			// 处理创建合约交易
			logger.Debug("Create contract tx")
			contractAddr, err := createContractTx(app.state.evmStateDB, txInAgg)
			if err != nil {
				logger.Debug("Contract create error: " + err.Error())
				return nil, err
			}
			logger.Debug("Contract created. contract address: " + contractAddr.Hex())
			err = database.InsertTxDetails(txDB)
			if err != nil {
				return nil, err
			}
			return contractAddr.Bytes(), nil
		} else {
			msg := fmt.Sprintf("Unknown tx")
			logger.Error(msg)
			return nil, errors.New(msg)
		}
	} else {
		// 执行合约
		logger.Debug("Execute contract result")
		_, err := app.callContractTx(app.state.evmStateDB, txInAgg)
		if err != nil {
			msg := fmt.Sprintf("Contract execute error: " + err.Error())
			logger.Error(msg)
			return nil, errors.New(msg)
		}
		logger.Debug("tx hash: " + txInAgg.Hash().Hex())
		err = database.InsertTxDetails(txDB)
		if err != nil {
			return nil, err
		}
		return txInAgg.Hash().Bytes(), nil
	}
}

// github.com/ethereum/go-ethereum@v1.12.0/core/txpool/txpool.go:600
// validateTxBasics checks whether a transaction is valid according to the consensus
// rules, but does not check state-dependent validation such as sufficient balance.
// This check is meant as an early check which only needs to be performed once,
// and does not require the pool mutex to be held.
func (app *EVMApplication) validateTxBasics(tx *evmtypes.Transaction) error {
	// Reject transactions over defined size to prevent DOS attacks
	if tx.Size() > uint64(txMaxSize) {
		return txpool.ErrOversizedData
	}
	// Check whether the init code size has been exceeded.
	if len(tx.Data()) > params.MaxInitCodeSize {
		return fmt.Errorf("%w: code size %v limit %v", core.ErrMaxInitCodeSizeExceeded, len(tx.Data()), params.MaxInitCodeSize)
	}
	// Transactions can't be negative. This may never happen using RLP decoded
	// transactions but may occur if you create a transaction using the RPC.
	if tx.Value().Sign() < 0 {
		return txpool.ErrNegativeValue
	}
	// Sanity check for extremely large numbers
	if tx.GasFeeCap().BitLen() > 256 {
		return core.ErrFeeCapVeryHigh
	}
	if tx.GasTipCap().BitLen() > 256 {
		return core.ErrTipVeryHigh
	}
	// Ensure gasFeeCap is greater than or equal to gasTipCap.
	if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
		return core.ErrTipAboveFeeCap
	}
	// Make sure the transaction is signed properly.
	if _, err := evmtypes.Sender(app.state.signer, tx); err != nil {
		return txpool.ErrInvalidSender
	}
	// Ensure the transaction has more gas than the basic tx fee.
	intrGas, err := core.IntrinsicGas(tx.Data(), tx.AccessList(), tx.To() == nil, true, true, true)
	if err != nil {
		return err
	}
	if tx.Gas() < intrGas {
		return core.ErrIntrinsicGas
	}
	return nil
}

// validateTx checks whether a transaction is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
func (app *EVMApplication) validateTx(tx *evmtypes.Transaction) error {
	// Signature has been checked already, this cannot error.
	from, _ := evmtypes.Sender(app.state.signer, tx)
	// Ensure the transaction adheres to nonce ordering
	if app.state.evmStateDB.GetNonce(from) > tx.Nonce() {
		return core.ErrNonceTooLow
	}
	// Transactor should have enough funds to cover the costs
	// cost == V + GP * GL
	balance := app.state.evmStateDB.GetBalance(from)
	if balance.Cmp(tx.Cost()) < 0 {
		return core.ErrInsufficientFunds
	}

	return nil
}

func createContractTx(evmState *state.StateDB, txInAgg *evmtypes.Transaction) (common.Address, error) {
	ret, contractAddr, leftGas, err := runtime.Create(txInAgg.Data(), &runtime.Config{
		State: evmState,
	})
	_ = leftGas
	_ = ret
	return contractAddr, err
}

// callContractTx only execute contract and don't update state
func (app *EVMApplication) executeContractTx(evmState *state.StateDB, txInAgg *ethereum.CallMsg) ([]byte, error) {
	ret, _, err := runtime.Call(*txInAgg.To, txInAgg.Data,
		&runtime.Config{
			ChainConfig: app.state.chainConfig,
			State:       evmState,
		},
	)
	return ret, err
}

// callContractTx call contract and update state
func (app *EVMApplication) callContractTx(evmState *state.StateDB, txInAgg *evmtypes.Transaction) ([]byte, error) {
	ret, _, err := runtime.Call(*txInAgg.To(), txInAgg.Data(),
		&runtime.Config{
			ChainConfig: app.state.chainConfig,
			GasLimit:    txInAgg.Gas(),
			GasPrice:    txInAgg.GasPrice(),
			Value:       txInAgg.Value(),
			State:       evmState,
		},
	)
	return ret, err
}

func (app *EVMApplication) handleMainTokenTx(evmState *state.StateDB, txInAgg *evmtypes.Transaction) error {
	fromAddress, _ := evmtypes.Sender(app.state.signer, txInAgg)
	a := big.Int{}
	fromNewBalance := a.Sub(evmState.GetBalance(fromAddress), txInAgg.Value())
	if fromNewBalance.Cmp(big.NewInt(0)) < 0 {
		return errors.New("insufficient balance")
	}
	evmState.SetBalance(fromAddress, fromNewBalance)

	b := big.Int{}
	toNewBalance := b.Add(evmState.GetBalance(*txInAgg.To()), txInAgg.Value())
	evmState.SetBalance(*txInAgg.To(), toNewBalance)
	return nil
}

func (app *EVMApplication) recoverEVMStateDB() error {
	app.state.nextTxNum = big.NewInt(0)
	app.state.signer = evmtypes.NewLondonSigner(ChainId)
	app.state.chainConfig = &params.ChainConfig{
		ChainID:             ChainId,
		HomesteadBlock:      new(big.Int),
		DAOForkBlock:        new(big.Int),
		DAOForkSupport:      false,
		EIP150Block:         new(big.Int),
		EIP155Block:         new(big.Int),
		EIP158Block:         new(big.Int),
		ByzantiumBlock:      new(big.Int),
		ConstantinopleBlock: new(big.Int),
		PetersburgBlock:     new(big.Int),
		IstanbulBlock:       new(big.Int),
		MuirGlacierBlock:    new(big.Int),
		BerlinBlock:         new(big.Int),
		LondonBlock:         new(big.Int),
	}
	app.state.evmStateDB, err = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		panic(err)
	}

	initAmount := big.NewInt(0)
	// 水龙头
	initAmount.SetString("1000000000000000000000000000000000000", 10)
	app.state.evmStateDB.SetBalance(common.HexToAddress("0xD64229dF1EB0354583F46e46580849B1572BB56d"), initAmount)

	itr, err := app.state.db.Iterator(nil, nil)
	if err != nil {
		panic(err)
	}
	for ; itr.Valid(); itr.Next() {
		if len(itr.Key()) >= len(evmTxsKey) && bytes.Equal(itr.Key()[:len(evmTxsKey)], evmTxsKey) && len(itr.Value()) > 0 {
			if len(string(itr.Value())) < 2 {
				logger.Error(fmt.Sprintf("recoverEVMStateDB error: %s", err.Error()))
				continue
			}
			txInAgg, err := convertReqTx2EvmTx(itr.Value())
			if err != nil {
				logger.Error(fmt.Sprintf("recoverEVMStateDB error: %s", err.Error()))
				continue
			}
			err = app.verifyEvmTx(txInAgg)
			if err != nil {
				logger.Error(fmt.Sprintf("recoverEVMStateDB error: %s", err.Error()))
				continue
			}
			_, err = app.executeEvmTx(txInAgg)
			if err != nil {
				logger.Error(fmt.Sprintf("recoverEVMStateDB error: %s", err.Error()))
				continue
			}
		}
	}
	return nil
}

func (app *EVMApplication) searchTxByAddress(address *common.Address) {
	itr, err := app.state.db.Iterator(nil, nil)
	if err != nil {
		panic(err)
	}
	for ; itr.Valid(); itr.Next() {
		if len(itr.Key()) >= len(evmTxsKey) && bytes.Equal(itr.Key()[:len(evmTxsKey)], evmTxsKey) && len(itr.Value()) > 0 {
			if len(string(itr.Value())) < 2 {
				logger.Error(fmt.Sprintf("recoverEVMStateDB error: %s", err.Error()))
				continue
			}
			txInAgg, err := convertReqTx2EvmTx(itr.Value())
			if err != nil {
				logger.Error(fmt.Sprintf("recoverEVMStateDB error: %s", err.Error()))
				continue
			}
			err = app.verifyEvmTx(txInAgg)
			if err != nil {
				logger.Error(fmt.Sprintf("recoverEVMStateDB error: %s", err.Error()))
				continue
			}
			_, err = app.executeEvmTx(txInAgg)
			if err != nil {
				logger.Error(fmt.Sprintf("recoverEVMStateDB error: %s", err.Error()))
				continue
			}
		}
	}
}

func (app *EVMApplication) verifyEvmTx(agg *evmtypes.Transaction) error {
	// verify tx
	err = app.validateTxBasics(agg)
	if err != nil {
		return err
	}
	err = app.validateTx(agg)
	if err != nil {
		return err
	}
	return nil
}
