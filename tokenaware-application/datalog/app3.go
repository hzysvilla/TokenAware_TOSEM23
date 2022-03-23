package datalog

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

var App3Info []TranInfo

func App3_Check(input []byte, caller string, conaddr string, debugflag int, calllayer int) {
	defer TimeTrack(time.Now(), &TotalConcolicExecTime)
	if conaddr == "0x0000000000000000000000000000000000000004" {
		return
	} // solve the precompile contract bug

	inputStr := hex.EncodeToString(input)

	if CurTxHash == DebugTx {
		fmt.Println("debug", debugflag, len(App3Info))
	}
	var new_conaddr string
	if calllayer > 1 {
		new_conaddr = "hzysflag:" + conaddr
	} else {
		return
	}

	if (len(inputStr) == 136 || len(inputStr) == 192) && "a9059cbb" == inputStr[:8] {
		// fmt.Println("call transfer input:", inputStr)
		amount, ok := new(big.Int).SetString(inputStr[72:136], 16)
		if ok {
			var transfer = TranInfo{
				AccFrom:  caller,
				AccTo:    common.HexToAddress(inputStr[8:72]).String(),
				Amount:   amount,
				ConAddr:  new_conaddr,
				FuncName: "transfer",
			}
			App3Info = append(App3Info, transfer)
		}
	}

	if len(inputStr) == 200 && "23b872dd" == inputStr[:8] {
		// fmt.Println("call transfer input:", inputStr)
		amount, ok := new(big.Int).SetString(inputStr[136:200], 16)
		if ok {
			var transfer = TranInfo{
				AccFrom:  common.HexToAddress(inputStr[8:72]).String(),
				AccTo:    common.HexToAddress(inputStr[72:136]).String(),
				Amount:   amount,
				ConAddr:  new_conaddr,
				FuncName: "transferFrom",
			}
			App3Info = append(App3Info, transfer)
		}
	}
}

func ClearApp3Info() {
	App3Info = App3Info[:0]
}

func IsCapturedApp3Info() bool {
	if len(App3Info) == 0 {
		return false
	}
	return true
}
