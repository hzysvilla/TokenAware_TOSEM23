package datalog

import (
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"sync"
)


  


var OyenteResultsDb *leveldb.DB
var ContractToTxDb *leveldb.DB

var newPatternDb *leveldb.DB

//打开数据库
func initLevelDb(path string) *leveldb.DB {
	//数据存储路径和一些初始文件
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		fmt.Println("failed to init leveldb!")
	}
	return db
}

// 存储key-value值到leveldb数据库中
func SaveToDb(key string, value string, db *leveldb.DB) {
/*	if db == nil {
		fmt.Println("db is nil, failed to save")
		return
	}
	db.Put([]byte(key), []byte(value), nil)
	//fmt.Println("saved", key, "=>", value)*/
}

// 根据key从leveldb中读取
func get(key string, db *leveldb.DB) []byte {
	if db == nil {
		fmt.Println("db is nil, failed to get")
		return nil
	}
	value, err := db.Get([]byte(key), nil)
	if err != nil {
		fmt.Println("failed to get value from leveldb!")
		return nil
	}
	return value
}

// 从数据库中读入之前保存的结果
func readResultsFromDb(results *sync.Map, db *leveldb.DB, flag int) {
	fmt.Println("reading result from leveldb....")
	iter := db.NewIterator(nil, nil)
	for iter.Next() {
		(*results).Store(string(iter.Key()), string(iter.Value()))
		if flag == 1 {
			Addr2OyenteFlag.Store(string(iter.Key()), true)
		}
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		fmt.Println("failed to read results from leveldb")
	}
	fmt.Println("read all results from leveldb!")
}
