// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package tests

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
)

// VMTest checks EVM execution without block or transaction context.
// See https://github.com/ethereum/tests/wiki/VM-Tests for the test format specification.
type VMTest struct {
	json vmJSON
}

func (t *VMTest) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &t.json)
}

type vmJSON struct {
	Env           stEnv                 `json:"env"`
	Exec          vmExec                `json:"exec"`
	Logs          common.UnprefixedHash `json:"logs"`
	GasRemaining  *math.HexOrDecimal64  `json:"gas"`
	Out           hexutil.Bytes         `json:"out"`
	Pre           core.GenesisAlloc     `json:"pre"`
	Post          core.GenesisAlloc     `json:"post"`
	PostStateRoot common.Hash           `json:"postStateRoot"`
}

//go:generate gencodec -type vmExec -field-override vmExecMarshaling -out gen_vmexec.go

type vmExec struct {
	Address  common.Address `json:"address"  gencodec:"required"`
	Caller   common.Address `json:"caller"   gencodec:"required"`
	Origin   common.Address `json:"origin"   gencodec:"required"`
	Code     []byte         `json:"code"     gencodec:"required"`
	Data     []byte         `json:"data"     gencodec:"required"`
	Value    *big.Int       `json:"value"    gencodec:"required"`
	GasLimit uint64         `json:"gas"      gencodec:"required"`
	GasPrice *big.Int       `json:"gasPrice" gencodec:"required"`
}

type vmExecMarshaling struct {
	Address  common.UnprefixedAddress
	Caller   common.UnprefixedAddress
	Origin   common.UnprefixedAddress
	Code     hexutil.Bytes
	Data     hexutil.Bytes
	Value    *math.HexOrDecimal256
	GasLimit math.HexOrDecimal64
	GasPrice *math.HexOrDecimal256
}

func (t *VMTest) Run(vmconfig vm.Config, _statedb *state.StateDB, snapshotter bool) (*state.StateDB, error){
	db:=rawdb.NewMemoryDatabase()
	var statedb *state.StateDB
	if _statedb ==nil{
		statedb = MakePreState(db, t.json.Pre)
		//fmt.Println("db",statedb)
	}else{
		//fmt.Println("statedb")
		statedb = _statedb
		//fmt.Println("db",statedb)
	}
	ret, gasRemaining, err := t.exec(statedb, vmconfig)
	if ret !=nil{
		//fmt.Println("ret: ",ret)
		//fmt.Println("HzysDebugInfo in vm_test_utils.go","ret: ",ret,"err:",err)
	}
	if gasRemaining ==0{
		//fmt.Println("gasRemaining: ",gasRemaining)
	}
	//check(err)
	return statedb,err

	/*if t.json.GasRemaining == nil {
		if err == nil {
			return fmt.Errorf("gas unspecified (indicating an error), but VM returned no error")
		}
		if gasRemaining > 0 {
			return fmt.Errorf("gas unspecified (indicating an error), but VM returned gas remaining > 0")
		}
		return nil
	}
	// Test declares gas, expecting outputs to match.
	if !bytes.Equal(ret, t.json.Out) {
		return fmt.Errorf("return data mismatch: got %x, want %x", ret, t.json.Out)
	}
	if gasRemaining != uint64(*t.json.GasRemaining) {
		return fmt.Errorf("remaining gas %v, want %v", gasRemaining, *t.json.GasRemaining)
	}
	for addr, account := range t.json.Post {
		for k, wantV := range account.Storage {
			if haveV := statedb.GetState(addr, k); haveV != wantV {
				return fmt.Errorf("wrong storage value at %x:\n  got  %x\n  want %x", k, haveV, wantV)
			}
		}
	}
	// if root := statedb.IntermediateRoot(false); root != t.json.PostStateRoot {
	// 	return fmt.Errorf("post state root mismatch, got %x, want %x", root, t.json.PostStateRoot)
	// }
	if logs := rlpHash(statedb.Logs()); logs != common.Hash(t.json.Logs) {
		return fmt.Errorf("post state logs hash mismatch: got %x, want %x", logs, t.json.Logs)
	}
	return nil*/
}

func (t *VMTest) exec(statedb *state.StateDB, vmconfig vm.Config) ([]byte, uint64, error) {
	evm := t.newEVM(statedb, vmconfig)
	e := t.json.Exec
	//statedb.SetCode(e.Address,common.String2Bytes("0x"+common.GlobalContractInfo.Bytecode))//set the contract code on the statedb


	return evm.Call(vm.AccountRef(e.Caller), e.Address, e.Data, e.GasLimit, e.Value)
}

func (t *VMTest) newEVM(statedb *state.StateDB, vmconfig vm.Config) *vm.EVM {
	canTransfer := func(db vm.StateDB, address common.Address, amount *big.Int) bool {
			return true
	}
	transfer := func(db vm.StateDB, sender, recipient common.Address, amount *big.Int) {
		db.SubBalance(sender, amount)
		db.AddBalance(recipient, amount)
	}
	context := vm.Context{
		CanTransfer: canTransfer,
		Transfer:    transfer,
		GetHash:     vmTestBlockHash,
		Origin:      t.json.Exec.Origin,
		Coinbase:    t.json.Env.Coinbase,
		BlockNumber: new(big.Int).SetUint64(t.json.Env.Number),
		Time:        new(big.Int).SetUint64(t.json.Env.Timestamp),
		GasLimit:    t.json.Env.GasLimit,
		Difficulty:  t.json.Env.Difficulty,
		GasPrice:    t.json.Exec.GasPrice,
	}
	//vmconfig.NoRecursion = true

	return vm.HzysNewEVM(context, statedb, params.MainnetChainConfig, vmconfig)
}

func vmTestBlockHash(n uint64) common.Hash {
	return common.BytesToHash(crypto.Keccak256([]byte(big.NewInt(int64(n)).String())))
}

func (t *VMTest) Getjson() (vmJSON){
	return t.json
}

func (t *VMTest) Setexec(addr common.Address,caller common.Address,origin common.Address, data []byte, value *big.Int,gaslimit uint64,gasprice *big.Int){
	t.json.Exec.Address = addr
	t.json.Exec.Caller = caller
	t.json.Exec.Origin = origin
	t.json.Exec.Data = data
	t.json.Exec.Value = value
	t.json.Exec.GasLimit= gaslimit
	t.json.Exec.GasPrice = gasprice
}
func (t *VMTest) Getenv()(number uint64, timestamp uint64){

	return t.json.Env.Number,t.json.Env.Timestamp
}

func (t *VMTest) Setenv(number uint64, timestamp uint64){
	t.json.Env.Number = number
	t.json.Env.Timestamp = timestamp
}

func (t *VMTest) Setenv1(coinbase common.Address, difficulty *big.Int, gasLimit *big.Int, number uint64, timestamp uint64){
	t.json.Env.Coinbase = coinbase
	t.json.Env.Difficulty = difficulty
	t.json.Env.GasLimit = gasLimit.Uint64()
	t.json.Env.Number = number
	t.json.Env.Timestamp = timestamp
}

//add new by hzy
//To Set Coinbase td GasLimit Number Timestamp
//func (t *VMTest) InitialEnv(BlockInfo common.StructBlockInfo){
func (t *VMTest) InitialEnv(){
	/*	t.json.Env.Coinbase= common.HexToAddress(BlockInfo.StrMiner)
		t.json.Env.Difficulty=common.String2Big(BlockInfo.StrDifficulty)
		t.json.Env.Number=uint64(common.String2Int(BlockInfo.StrBlockNumber))
		t.json.Env.GasLimit=uint64(common.String2Int(BlockInfo.StrGasLimit))
		t.json.Env.Timestamp=uint64(common.String2Int(BlockInfo.StrTimeStamp))*/
	t.json.Env.Coinbase= common.HexToAddress( "0x2a5994b501E6A560e727b6C2DE5D856396aaDd38")
	t.json.Env.Difficulty=big.NewInt(0)
	t.json.Env.Number=uint64(999)
	t.json.Env.GasLimit=uint64(9999999999999)
	t.json.Env.Timestamp=uint64(0)
}
//add end


func (t *VMTest) Setdiff(difficulty *big.Int){
	t.json.Env.Difficulty = difficulty
}

func (t *VMTest) Setdata(data []byte){
	t.json.Exec.Data = data
}


func (t *VMTest) Setaddress(address common.Address){
	t.json.Exec.Address = address
}


func (t *VMTest) Setcaller(address common.Address){
	t.json.Exec.Caller = address
}
func (t *VMTest) Setvalue(value *big.Int){
	t.json.Exec.Value = value
}

func (t *VMTest) Setcode(code []byte){
	t.json.Exec.Code = code
}

func (t *VMTest) Create(vmconfig vm.Config,snapshotter bool)(*state.StateDB, common.Address,error,[]byte){
	db:= rawdb.NewMemoryDatabase()
	statedb := MakePreState(db, t.json.Pre)
	evm := t.newEVM(statedb, vmconfig)
	e := t.json.Exec
	//statedb.SetCode(e.Address,common.String2Bytes("0x"+common.GlobalContractInfo.Bytecode))
	//t.json.Exec.Data=common.String2Bytes("0x"+common.GlobalContractInfo.Bytecode)
	ret,address,gas,err,RuntimeBytecode :=evm.HzysCreate(vm.AccountRef(e.Caller), e.Data, e.GasLimit, e.Value)
	if ret == nil{
		//	fmt.Println("ret: nil")
	}
	if gas == 0{
		//	fmt.Println("gasRemaining: ",gas)
	}
	//fmt.Println(address.Hex(),gas)
	return statedb,address,err,RuntimeBytecode
}
