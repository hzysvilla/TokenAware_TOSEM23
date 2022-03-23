package datalog

import (
	"math/big"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"time"
)

type TranInfo struct {
	AccFrom 	string
	AccTo 		string
	Amount 		*big.Int
	ConAddr 	string

	FuncName 	string
}

var FunInfos []TranInfo
var EventInfos []TranInfo

func GetFunInfo(input []byte, caller string, conaddr string) {
	defer TimeTrack(time.Now(), &TotalConcolicExecTime)
	if conaddr == "0x0000000000000000000000000000000000000004" {
		return 
	} // solve the precompile contract bug

	inputStr := hex.EncodeToString(input)

	if (len(inputStr) == 136 || len(inputStr) == 192) && "a9059cbb" == inputStr[:8] {
		// fmt.Println("call transfer input:", inputStr)
		amount, ok := new(big.Int).SetString(inputStr[72:136], 16)
		if ok {
			var transfer = TranInfo{
				AccFrom:   caller,
				AccTo:     common.HexToAddress(inputStr[8:72]).String(),
				Amount: amount,
				ConAddr: conaddr,
				FuncName: "transfer",
			}
			FunInfos = append(FunInfos, transfer)
		}
	}

	if len(inputStr) == 200 && "23b872dd" == inputStr[:8] {
		// fmt.Println("call transfer input:", inputStr)
		amount, ok := new(big.Int).SetString(inputStr[136:200], 16)
		if ok {
			var transfer = TranInfo{
				AccFrom:   common.HexToAddress(inputStr[8:72]).String(),
				AccTo:     common.HexToAddress(inputStr[72:136]).String(),
				Amount: amount,
				ConAddr: conaddr,
				FuncName: "transferFrom",
			}
			FunInfos = append(FunInfos, transfer)
		}
	}


}

func IsCapturedEvent() bool {
	if len(EventInfos) == 0 {
		return false
	}
	return true
}

func IsCapturedFun() bool {
	if len(FunInfos) == 0 {
		return false
	}
	return true
}

func ClearTranInfos() {
	EventInfos = EventInfos[:0]
	FunInfos = FunInfos[:0]
}
