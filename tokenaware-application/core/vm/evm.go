// Copyright 2014 The go-ethereum Authors
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

package vm

import (
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"

	// zws
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/datalog"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	// CanTransferFunc is the signature of a transfer guard function
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	// TransferFunc is the signature of a transfer function
	TransferFunc func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the n'th block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) common.Hash
)

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *EVM, contract *Contract, input []byte, readOnly bool) ([]byte, error) {
	hzysflag := false
	if contract.CodeAddr != nil {
		precompiles := PrecompiledContractsHomestead
		if evm.chainRules.IsByzantium {
			precompiles = PrecompiledContractsByzantium
		}
		if evm.chainRules.IsIstanbul {
			precompiles = PrecompiledContractsIstanbul
		}
		if p := precompiles[*contract.CodeAddr]; p != nil {
			if evm.IsTxStart() && datalog.CurTxHash == datalog.DebugTx {
				fmt.Println("hit precomplier", 1)
				hzysflag = true
			}
			return RunPrecompiledContract(p, input, contract)
		}
	}

	if evm.IsTxStart() && hzysflag == true {
		fmt.Println("run in1", contract.CodeAddr.String())
	}

	if evm.IsTxStart() && datalog.CurTxHash == datalog.DebugTx {
		fmt.Println("run in 2 ", contract.CodeAddr.String())
	}

	if evm.IsTxStart() && len(contract.Code) == 0 {
		datalog.App3_Check(input, evm.curcalladdr, contract.CodeAddr.String(), 2, evm.call_layer)
	}
	for _, interpreter := range evm.interpreters {
		if interpreter.CanRun(contract.Code) {
			if evm.interpreter != interpreter {
				// Ensure that the interpreter pointer is set back
				// to its current value upon return.
				defer func(i Interpreter) {
					evm.interpreter = i
				}(evm.interpreter)
				evm.interpreter = interpreter
			}
			return interpreter.Run(contract, input, readOnly)
		}
	}
	return nil, ErrNoCompatibleInterpreter
}

// Context provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	GetHash GetHashFunc

	// Message information
	Origin   common.Address // Provides information for ORIGIN
	GasPrice *big.Int       // Provides information for GASPRICE

	// Block information
	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // Provides information for GASLIMIT
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        *big.Int       // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
type EVM struct {
	// Context provides auxiliary blockchain related information
	Context
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// evm.
	vmConfig Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.
	interpreters []Interpreter
	interpreter  Interpreter
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically
	abort int32
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	callGasTemp uint64

	// zws
	isTxStart bool
	//add by hzy
	PatternExistFlag bool
	//add end

	curcalladdr string
	calladdrs   []string
	call_layer  int

	opactive    map[string]bool
	pc2pattern  map[string]string
	valueoffset int

	loc2addr      map[[32]byte]string
	sloadloc2val  map[[32]byte]*big.Int
	sstoreloc2val map[[32]byte]*big.Int
}

// NewEVM returns a new EVM. The returned EVM is not thread safe and should
// only ever be used *once*.
func NewEVM(ctx Context, statedb StateDB, chainConfig *params.ChainConfig, vmConfig Config) *EVM {
	evm := &EVM{
		Context:      ctx,
		StateDB:      statedb,
		vmConfig:     vmConfig,
		chainConfig:  chainConfig,
		chainRules:   chainConfig.Rules(ctx.BlockNumber),
		interpreters: make([]Interpreter, 0, 1),

		opactive:   make(map[string]bool),
		pc2pattern: make(map[string]string),

		loc2addr:      make(map[[32]byte]string),
		sloadloc2val:  make(map[[32]byte]*big.Int),
		sstoreloc2val: make(map[[32]byte]*big.Int),
	}
	if chainConfig.IsEWASM(ctx.BlockNumber) {
		// to be implemented by EVM-C and Wagon PRs.
		// if vmConfig.EWASMInterpreter != "" {
		//  extIntOpts := strings.Split(vmConfig.EWASMInterpreter, ":")
		//  path := extIntOpts[0]
		//  options := []string{}
		//  if len(extIntOpts) > 1 {
		//    options = extIntOpts[1..]
		//  }
		//  evm.interpreters = append(evm.interpreters, NewEVMVCInterpreter(evm, vmConfig, options))
		// } else {
		// 	evm.interpreters = append(evm.interpreters, NewEWASMInterpreter(evm, vmConfig))
		// }
		panic("No supported ewasm interpreter yet.")
	}

	// vmConfig.EVMInterpreter will be used by EVM-C, it won't be checked here
	// as we always want to have the built-in EVM as the failover option.
	evm.interpreters = append(evm.interpreters, NewEVMInterpreter(evm, vmConfig))
	evm.interpreter = evm.interpreters[0]

	return evm
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *EVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

// Cancelled returns true if Cancel has been called
func (evm *EVM) Cancelled() bool {
	return atomic.LoadInt32(&evm.abort) == 1
}

// Interpreter returns the current interpreter
func (evm *EVM) Interpreter() Interpreter {
	return evm.interpreter
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}

	if evm.IsTxStart() && datalog.CurTxHash == datalog.DebugTx {
		fmt.Println("Call")
	}

	// add by zws
	if evm.IsTxStart() {
		evm.curcalladdr = addr.String()
		evm.calladdrs = append(evm.calladdrs, addr.String())
		evm.call_layer += 1
		datalog.GetFunInfo(input, caller.Address().String(), addr.String())
		oyenteres := datalog.WaitOyenteRes(addr.String()) //check and ensure the contract has processed by goroutine
		//fmt.Println("\nevm.call() evm.go(247lines)\ncurrent Txhash",datalog.CurTxHash,"\ncontract addr:"  ,"\nmodeling string",oyenteres,"\n")
		evm.ProceOyenteRes(oyenteres)
	}
	//add end

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	if !evm.StateDB.Exist(addr) {
		precompiles := PrecompiledContractsHomestead
		if evm.chainRules.IsByzantium {
			precompiles = PrecompiledContractsByzantium
		}
		if evm.chainRules.IsIstanbul {
			precompiles = PrecompiledContractsIstanbul
		}
		if precompiles[addr] == nil && evm.chainRules.IsEIP158 && value.Sign() == 0 {
			// Calling a non existing account, don't do anything, but ping the tracer
			if evm.vmConfig.Debug && evm.depth == 0 {
				evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)
				evm.vmConfig.Tracer.CaptureEnd(ret, 0, 0, nil)
			}
			// zws
			if evm.IsTxStart() {
				datalog.App3_Check(input, caller.Address().String(), addr.String(), 1, evm.call_layer)
				evm.calladdrs = evm.calladdrs[:evm.call_layer-1]
				evm.call_layer -= 1

				if evm.call_layer > 0 {
					evm.curcalladdr = evm.calladdrs[evm.call_layer-1]
				} else {
					evm.curcalladdr = ""
				}
				// fmt.Println("debug precompiles")
				// fmt.Println("calladdrs: ", evm.calladdrs)
				// fmt.Println("call_layer: ", evm.call_layer)
			}
			//

			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}

	evm.Transfer(evm.StateDB, caller.Address(), to.Address(), value)
	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))
	if evm.IsTxStart() && addr.String() == "0x0000000000000000000000000000000000000000" {
		datalog.App3_Check(input, caller.Address().String(), addr.String(), 0, evm.call_layer)
	}

	// Even if the account has no code, we need to continue because it might be a precompile
	start := time.Now()

	// Capture the tracer start/end events in debug mode
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)

		defer func() { // Lazy evaluation of the parameters
			evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
		}()
	}
	ret, err = run(evm, contract, input, false)

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	// zws
	if evm.IsTxStart() {
		evm.calladdrs = evm.calladdrs[:evm.call_layer-1]
		evm.call_layer -= 1

		if evm.call_layer > 0 {
			evm.curcalladdr = evm.calladdrs[evm.call_layer-1]
		} else {
			evm.curcalladdr = ""
		}

		for k, v := range datalog.SStoreLoc2CoreData {
			datalog.CoreDataArr = append(datalog.CoreDataArr, v)
			delete(datalog.SStoreLoc2CoreData, k)
		}

		for k, _ := range evm.sloadloc2val {
			delete(evm.sloadloc2val, k)
		}
		// fmt.Println("debug end")
		// fmt.Println("calladdrs: ", evm.calladdrs)
		// fmt.Println("call_layer: ", evm.call_layer)
	}
	//

	return ret, contract.Gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}

	// add by zws
	if evm.IsTxStart() {
		evm.curcalladdr = addr.String()
		evm.calladdrs = append(evm.calladdrs, addr.String())
		evm.call_layer += 1
		datalog.GetFunInfo(input, caller.Address().String(), addr.String())
		oyenteres := datalog.WaitOyenteRes(addr.String()) //check and ensure the contract has processed by goroutine
		//fmt.Println("\nevm.call() evm.go(247lines)\ncurrent Txhash",datalog.CurTxHash,"\ncontract addr:"  ,"\nmodeling string",oyenteres,"\n")
		evm.ProceOyenteRes(oyenteres)
	}
	//add end

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)
	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	if evm.IsTxStart() && addr.String() == "0x0000000000000000000000000000000000000000" {
		datalog.App3_Check(input, caller.Address().String(), addr.String(), 0, evm.call_layer)
	}

	ret, err = run(evm, contract, input, false)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	// zws
	if evm.IsTxStart() {
		evm.calladdrs = evm.calladdrs[:evm.call_layer-1]
		evm.call_layer -= 1

		if evm.call_layer > 0 {
			evm.curcalladdr = evm.calladdrs[evm.call_layer-1]
		} else {
			evm.curcalladdr = ""
		}

		for k, v := range datalog.SStoreLoc2CoreData {
			datalog.CoreDataArr = append(datalog.CoreDataArr, v)
			delete(datalog.SStoreLoc2CoreData, k)
		}

		for k, _ := range evm.sloadloc2val {
			delete(evm.sloadloc2val, k)
		}
		// fmt.Println("debug end")
		// fmt.Println("calladdrs: ", evm.calladdrs)
		// fmt.Println("call_layer: ", evm.call_layer)
	}
	//

	return ret, contract.Gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)

	// add by zws
	if evm.IsTxStart() {
		evm.curcalladdr = addr.String()
		evm.calladdrs = append(evm.calladdrs, addr.String())
		evm.call_layer += 1
		datalog.GetFunInfo(input, caller.Address().String(), addr.String())
		oyenteres := datalog.WaitOyenteRes(addr.String()) //check and ensure the contract has processed by goroutine
		//fmt.Println("\nevm.call() evm.go(247lines)\ncurrent Txhash",datalog.CurTxHash,"\ncontract addr:"  ,"\nmodeling string",oyenteres,"\n")
		evm.ProceOyenteRes(oyenteres)
	}
	//add end

	// Initialise a new contract and make initialise the delegate values
	contract := NewContract(caller, to, nil, gas).AsDelegate()
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))
	if evm.IsTxStart() && addr.String() == "0x0000000000000000000000000000000000000000" {
		datalog.App3_Check(input, caller.Address().String(), addr.String(), 0, evm.call_layer)
	}

	ret, err = run(evm, contract, input, false)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	// zws
	if evm.IsTxStart() {
		evm.calladdrs = evm.calladdrs[:evm.call_layer-1]
		evm.call_layer -= 1

		if evm.call_layer > 0 {
			evm.curcalladdr = evm.calladdrs[evm.call_layer-1]
		} else {
			evm.curcalladdr = ""
		}

		for k, v := range datalog.SStoreLoc2CoreData {
			datalog.CoreDataArr = append(datalog.CoreDataArr, v)
			delete(datalog.SStoreLoc2CoreData, k)
		}

		for k, _ := range evm.sloadloc2val {
			delete(evm.sloadloc2val, k)
		}
		// fmt.Println("debug end")
		// fmt.Println("calladdrs: ", evm.calladdrs)
		// fmt.Println("call_layer: ", evm.call_layer)
	}
	//

	return ret, contract.Gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, new(big.Int), gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	// We do an AddBalance of zero here, just in order to trigger a touch.
	// This doesn't matter on Mainnet, where all empties are gone at the time of Byzantium,
	// but is the correct thing to do and matters on other networks, in tests, and potential
	// future scenarios
	evm.StateDB.AddBalance(addr, bigZero)

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in Homestead this also counts for code storage gas errors.
	ret, err = run(evm, contract, input, true)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

type codeAndHash struct {
	code []byte
	hash common.Hash
}

func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

// create creates a new contract using code as deployment code.
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	// Ensure there's no existing contract already at the designated address
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	evm.Transfer(evm.StateDB, caller.Address(), address, value)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)

	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, address, gas, nil
	}

	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), address, true, codeAndHash.code, gas, value)
	}
	start := time.Now()

	ret, err := run(evm, contract, nil, false)

	// check whether the max code size has been exceeded
	maxCodeSizeExceeded := evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize
	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil && !maxCodeSizeExceeded {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if maxCodeSizeExceeded || (err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas)) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	// Assign err if contract code size exceeds the max while the err is still empty.
	if maxCodeSizeExceeded && err == nil {
		err = errMaxCodeSizeExceeded
	}
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
	}
	return ret, address, contract.Gas, err

}

// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses sha3(0xff ++ msg.sender ++ salt ++ sha3(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), common.BigToHash(salt), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr)
}

//add by hzy on 20-9-25
//To Get runtimecode when preload : ( fuck off)

func HzysNewEVM(ctx Context, statedb StateDB, chainConfig *params.ChainConfig, vmConfig Config) *EVM {
	evm := &EVM{
		Context:      ctx,
		StateDB:      statedb,
		vmConfig:     vmConfig,
		chainConfig:  chainConfig,
		chainRules:   chainConfig.Rules(ctx.BlockNumber),
		interpreters: make([]Interpreter, 0, 1),

		opactive:   make(map[string]bool),
		pc2pattern: make(map[string]string),

		loc2addr:      make(map[[32]byte]string),
		sloadloc2val:  make(map[[32]byte]*big.Int),
		sstoreloc2val: make(map[[32]byte]*big.Int),
	}
	if chainConfig.IsEWASM(ctx.BlockNumber) {
		// to be implemented by EVM-C and Wagon PRs.
		// if vmConfig.EWASMInterpreter != "" {
		//  extIntOpts := strings.Split(vmConfig.EWASMInterpreter, ":")
		//  path := extIntOpts[0]
		//  options := []string{}
		//  if len(extIntOpts) > 1 {
		//    options = extIntOpts[1..]
		//  }
		//  evm.interpreters = append(evm.interpreters, NewEVMVCInterpreter(evm, vmConfig, options))
		// } else {
		// 	evm.interpreters = append(evm.interpreters, NewEWASMInterpreter(evm, vmConfig))
		// }
		panic("No supported ewasm interpreter yet.")
	}

	evm.chainRules.IsHomestead = true
	evm.chainRules.IsEIP150 = true
	evm.chainRules.IsEIP155 = true
	evm.chainRules.IsEIP158 = true

	// vmConfig.EVMInterpreter will be used by EVM-C, it won't be checked here
	// as we always want to have the built-in EVM as the failover option.
	evm.interpreters = append(evm.interpreters, HzysNewEVMInterpreter(evm, vmConfig))
	evm.interpreter = evm.interpreters[0]

	return evm
}

func (evm *EVM) HzysCreate(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error, RuntimeBytecode []byte) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.hzycreate(caller, &codeAndHash{code: code}, gas, value, contractAddr)
}

// create creates a new contract using code as deployment code.
func (evm *EVM) hzycreate(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error, []byte) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > 0 {
		return nil, common.Address{}, gas, ErrDepth, nil
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	//evm.Transfer(evm.StateDB, caller.Address(), address, value)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)

	start := time.Now()

	ret, err := run(evm, contract, nil, false)

	// check whether the max code size has been exceeded
	maxCodeSizeExceeded := evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize
	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil && !maxCodeSizeExceeded {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}
	var RuntimeBytecode = evm.StateDB.GetCode(address)

	//revert it any way
	evm.StateDB.RevertToSnapshot(snapshot)

	// Assign err if contract code size exceeds the max while the err is still empty.
	if maxCodeSizeExceeded && err == nil {
		err = errMaxCodeSizeExceeded
	}
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
	}
	return ret, address, contract.Gas, err, RuntimeBytecode

}

//add end

// ChainConfig returns the environment's chain configuration
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

// zws
func (evm *EVM) IsTxStart() bool        { return evm.isTxStart }
func (evm *EVM) SetTxStart(status bool) { evm.isTxStart = status }

func (evm *EVM) ProceOyenteRes(input string) {
	defer datalog.TimeTrack(time.Now(), &datalog.TotalConcolicExecTime)
	//fmt.Println("pattern:",input)
	if input == "" {
		return
	}
	General_Patterns := strings.Split(input, "\n")
	if len(General_Patterns) > 0 {
		datalog.InitTargetOpcode()                   //init target opcode list
		evm.valueoffset = 0                          //the typeIII's offset is zero//evm.valueoffset = 128
		evm.PatternExistFlag = true                  // specify the pattern exist
		for i := 0; i < len(General_Patterns); i++ { //the last element is empty
			//General_pattern[0] should be symbolic expression, General_pattern[1] is pc seq.
			General_pattern := strings.Split(General_Patterns[i], "||")
			if strings.Contains(General_pattern[0], "noo") || General_Patterns[i] == "" || General_Patterns[i] == "\n" { //exclude the result that oyente can't match event and
				continue
			}
			if len(General_pattern) != 2 {
				fmt.Println("\n=====\nhzysdebugInfo:error", "the length of opcode_pattern mismatch.\n", "GeneralPattern is", General_Patterns,
					"error pattern is:", General_pattern, "\nindex:", i, "\naddr", evm.curcalladdr, "\n======")
			} else {
				//process opcodes
				pattern_opcode := General_pattern[0]
				for OpcodeK, OpcodeV := range datalog.TargetOpcode {
					if strings.Contains(pattern_opcode, OpcodeK) {
						evm.opactive[OpcodeV] = true
					}
				}
				//process pc
				pattern_pc := strings.Split(General_pattern[1], ",") //get pc seqs
				if len(pattern_pc) == 0 {
					fmt.Println("hzysdebugInfo", "the length of opcode_pattern mismatch.\n error pattern is:", General_pattern)
				}
				pattern_pc[0] = strings.Replace(pattern_pc[0], " ", "", -1) //eliminate
				for k := 0; k < len(pattern_pc); k++ {
					pc_addr := pattern_pc[k]
					pc_addr = pc_addr + evm.curcalladdr
					evm.pc2pattern[pc_addr] = pattern_opcode
				}
			}
		}
		/*fmt.Println("\nhzysDebugInfo","ProceOyenteRes\n","Contract addr:",evm.curcalladdr)
		fmt.Println("pc Array:",evm.pc2pattern)
		fmt.Println("opactivelist",evm.opactive,"\n")*/
	}
}
