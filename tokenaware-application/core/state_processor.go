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

package core

import (
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"

	// zws
	"fmt"
	"time"

	// "encoding/hex"
	"github.com/ethereum/go-ethereum/datalog"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit())
	)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	// Iterate over and process the individual transactions

	for i, tx := range block.Transactions() {
		//add by hzy 20-9-18
		//to record the current tx hash
		datalog.CurTxHash = tx.Hash().String()
		//add end
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, usedGas, cfg)
		if err != nil {
			return nil, nil, 0, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)

	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles())

	// zws
	nowBlockNumber := block.Number().Int64()
	if nowBlockNumber%100000 == 0 {
		fmt.Println("\nblock Num: ", nowBlockNumber)
		fmt.Println("wait time: ", datalog.TotalWaitTime)
		fmt.Println("procres time: ", datalog.TotalProcTime)
		//fmt.Println("AnaTx time: ", datalog.TotalAnaTime)//write ret to file
		//fmt.Println("Total prewrite time: ",datalog.TotalPreWreteTime)
		fmt.Println("oyente exec count: ", datalog.CountResult.GetOyenteExecCount())
		fmt.Println("oyente cache count: ", datalog.CountResult.GetOyenteCacheCount())
		//fmt.Println("evm wait count",datalog.CountResult.GetWaitContractCount())
		fmt.Println("ConcolicExec time: ", datalog.TotalConcolicExecTime)
		ReportTime()
	}
	// if nowBlockNumber == 3094934 {
	// 	//time.Sleep(10 * time.Minute)
	// 	os.Exit(11)
	// }
	/*if nowBlockNumber%10000 == 0 {
		t := time.Now().UnixNano() / 1e9
		content := block.Number().String() + "  " + strconv.FormatInt(t, 10)

	datalog.WriteToFile(content, datalog.TimePath, true)
	}*/

	if nowBlockNumber > 9000000 {
		//datalog.OyenteResults.Range(func(k, v interface{}) bool {
		//	if len(v.(string))!=0 {
		//		fmt.Println(k.(string),"#",v.(string))
		//	}
		//	return true
		//})
		//ReportTime()
		/*		for k,v := range(datalog.ContractWaitCounter){
				fmt.Println(k,"#",v)
			}*/
		datalog.DWg.Wait()
		datalog.Wg.Wait()
		fmt.Println("!!!!!!!!!!", nowBlockNumber, "!!!!!!!!!!")
		os.Exit(0)
	}

	return receipts, allLogs, *usedGas, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number))
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	context := NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)

	// zws
	vmenv.SetTxStart(true)

	_, gas, failed, err := ApplyMessage(vmenv, msg, gp)
	if err != nil {

		// zws
		datalog.ClearApp3Info()
		datalog.ClearTranInfos()
		datalog.ClearCoreDataArr()

		return nil, err
	}
	// Update the state with pending changes
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += gas

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing whether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = gas
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
		// zws
		datalog.ContractToTxHash.Store(receipt.ContractAddress.String(), tx.Hash().String())
		//datalog.SaveToDb(receipt.ContractAddress.String(), tx.Hash().String(), datalog.ContractToTxDb)
		//
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = statedb.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())

	//add by zws on 20-9-29
	datalog.CurTxHash = tx.Hash().String()
	//datalog.HzysRetWrite()//write the final results
	datalog.TxConsistAna()

	datalog.ClearApp3Info()
	datalog.ClearCoreDataArr()
	datalog.ClearTranInfos()
	//add end
	// if strings.Compare(tx.Hash().String(), "0x05a7b7ced73705e50e32f329d9b4f60d291bd3b1bff3ca0127fef561c6b7eb83") == 0 {
	// 	fmt.Println("FIND TX!")
	// 	datalog.FindTx = false
	// }
	return receipt, err
}

func ReportTime() {
	fmt.Printf("StartTime :%d:%d:%d\n", datalog.StartTime.Hour(), datalog.StartTime.Minute(), datalog.StartTime.Second())
	NowTime := time.Now()
	fmt.Printf("EndTime :%d:%d:%d\n", NowTime.Hour(), NowTime.Minute(), NowTime.Second())
	var ExecTime = NowTime.UnixNano() - datalog.StartTime.UnixNano()
	fmt.Println("Total Time:", (ExecTime/1e9)/60, "mins ", ExecTime/1e9, "s")
}
