package database

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/agg-chain/aggchain/libs/log"
	_ "github.com/lib/pq"
	"os"
)

type TxDetailsInfo struct {
	Id       int64  `json:"id,omitempty"`
	TxHash   string `json:"tx_hash,omitempty"`
	TxFrom   string `json:"tx_from,omitempty"`
	TxTo     string `json:"tx_to,omitempty"`
	RawData  string `json:"raw_data,omitempty"`
	TxValue  string `json:"tx_value,omitempty"`
	TxHeight int32  `json:"tx_height,omitempty"`
}

var (
	logger       log.Logger
	enableSaveDb = false
	db           *sql.DB
	err          error
	host         = os.Getenv("dbhost")
	user         = os.Getenv("dbuser")
	password     = os.Getenv("dbpassword")
	name         = os.Getenv("dbname")
	port         = os.Getenv("dbport")
)

func init() {
	logger = log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	logger = logger.With("module", "evmdatabase")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		host, user, password, name, port)
	db, err = sql.Open("postgres", dsn)
	err = db.Ping()
	if err != nil {
		logger.Error(err.Error())
		logger.Info("db config is wrong. Skip save to db task!")
		return
	}
	enableSaveDb = true
	logger.Info("enable db")
}

func QueryRelationTxDetails(from, to string, start, end uint64) ([]*TxDetailsInfo, error) {
	if !enableSaveDb {
		return nil, nil
	}
	var txs []*TxDetailsInfo
	rows, err := db.Query("SELECT id,tx_hash,tx_height,tx_from,tx_to,tx_value,raw_data FROM tx_details where tx_from = $1 or tx_to = $2 order by id limit $3 offset $4", from, to, end, start)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		tx := &TxDetailsInfo{}
		err = rows.Scan(&tx.Id, &tx.TxHash, &tx.TxHeight, &tx.TxFrom, &tx.TxTo, &tx.TxValue, &tx.RawData)
		if err != nil {
			continue
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

func InsertTxDetails(tx *TxDetailsInfo) error {
	if !enableSaveDb {
		return nil
	}
	count := db.QueryRow("SELECT count(*) FROM tx_details where tx_hash = $1", tx.TxHash)
	countRes := 0
	err := count.Scan(&countRes)
	if err != nil {
		return err
	}

	var res sql.Result
	if countRes == 0 {
		countAll := db.QueryRow("SELECT count(*) FROM tx_details")
		countAllRes := 0
		err := countAll.Scan(&countAllRes)
		res, err = db.Exec(
			"INSERT INTO tx_details(id,tx_hash,tx_height,tx_from,tx_to,tx_value,raw_data) VALUES($1,$2,$3,$4,$5,$6,$7)",
			countAllRes+1, tx.TxHash, tx.TxHeight, tx.TxFrom, tx.TxTo, tx.TxValue, tx.RawData)
		if err != nil {
			return err
		}
	} else {
		stmt, err := db.Prepare("UPDATE tx_details SET tx_height=$1,tx_from=$2,tx_to=$3,tx_value=$4,raw_data=$5 WHERE tx_hash = $6")
		if err != nil {
			return err
		}

		res, err = stmt.Exec(tx.TxHeight, tx.TxFrom, tx.TxTo, tx.TxValue, tx.RawData, tx.TxHash)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("affected row is 0")
	}
	return nil
}
