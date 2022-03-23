package datalog

import (
	"sync/atomic"
)

type Counter struct {
	blockNumber         uint64
	txCount             uint64
	diffTxCount         uint64
	sameTxCount         uint64
	contractCount       uint64
	diffTokenCount      uint64
	sameTokenCount      uint64
	tokenCount          uint64
	oyenteCacheCount    uint64
	oyenteExecCount     uint64
	patternTypesCount   uint64 // pattern个数
	multiCallCount      uint64 //跨合约交易个数
	multiCallTokenCount uint64 //是Token的跨合约交易个数
	WaitContractCount uint64 //the wait times of this contract
	//patternTypesTxCount uint64
}

var CountResult Counter

func (count *Counter) InitCounter() {
	count.blockNumber = 0
	count.txCount = 0
	count.diffTxCount = 0
	count.sameTxCount = 0
	count.contractCount = 0
	count.diffTokenCount = 0
	count.sameTokenCount = 0
	count.tokenCount = 0
	count.oyenteCacheCount = 0
	count.patternTypesCount = 0
	count.multiCallCount = 0
	count.multiCallTokenCount = 0
	count.WaitContractCount = 0
}

func (count *Counter) setBlockNum(num uint64) {
	atomic.StoreUint64(&count.blockNumber, num)
}

func (count *Counter) addTxCount() {
	atomic.AddUint64(&count.txCount, 1)
}

func (count *Counter) addDiffTxCount() {
	atomic.AddUint64(&count.diffTxCount, 1)
}

func (count *Counter) addSameTxCount() {
	atomic.AddUint64(&count.sameTxCount, 1)
}

func (count *Counter) addContractCount() {
	atomic.AddUint64(&count.contractCount, 1)
}

func (count *Counter) addDiffTokenCount() {
	atomic.AddUint64(&count.diffTokenCount, 1)
}

func (count *Counter) addSameTokenCount() {
	atomic.AddUint64(&count.sameTokenCount, 1)
}

func (count *Counter) addTokenCount() {
	atomic.AddUint64(&count.tokenCount, 1)
}

func (count *Counter) addOyenteCacheCount() {
	atomic.AddUint64(&count.oyenteCacheCount, 1)
}

func (count *Counter) addOyenteExecCount() {
	atomic.AddUint64(&count.oyenteExecCount, 1)
}

func (count *Counter) addMultiCallCount() {
	atomic.AddUint64(&count.multiCallCount, 1)
}

func (count *Counter) addMultiCallTokenCount() {
	atomic.AddUint64(&count.multiCallTokenCount, 1)
}

func (count *Counter) addWaitContractCount() {
	atomic.AddUint64(&count.WaitContractCount, 1)
}

func (count *Counter) GetOyenteExecCount() uint64 {
	return atomic.LoadUint64(&count.oyenteExecCount)
}

func (count *Counter) GetOyenteCacheCount() uint64 {
	return atomic.LoadUint64(&count.oyenteCacheCount)
}

func (count *Counter) GetWaitContractCount() uint64 {
	return atomic.LoadUint64(&count.WaitContractCount)
}
