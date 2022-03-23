package datalog

import (
	"math/big"
)

type CoreData struct {
	Account 		string
	Val 			*big.Int

	Pattern 		string
	ConAddr 		string
	CallLayer 		int
}

var SStoreLoc2CoreData = make(map[string]CoreData)

var CoreDataArr []CoreData

var TargetOpcode map[string]string  //the list of opcodes which one we should check

func ClearCoreDataArr() {
	CoreDataArr = CoreDataArr[:0]
}

func IsCapturedCoreData() bool {
	if len(CoreDataArr) == 0 {
		return false
	}
	return true
}

//add by hzy 20-9-18
//the key word that the symbolic expression will use
func InitTargetOpcode(){
	TargetOpcode =map[string]string{"and":"AND","or":"OR","xor":"XOR","not":"NOT","byte":"BYTE",
		"sha3":"SHA3","add":"ADD","sub":"SUB","Cload":"CALLDATALOAD","div":"DIV","mul":"MUL",
		"msg":"CALLER", "mem":"MLOAD","shr":"SHR","shl":"SHL","sar":"SAR", "mod":"MOD","smod":"SMOD",
		"addmod":"ADDMOD", "mulmod":"MULMOD","exp":"EXP","signextend":"SIGNEXTEND", "lt":"LT","gt":"GT",
		"slt":"SLT","sgt":"SGT","eq":"EQ","iszero":"ISZERO"}
}
var TxAddr string
//add end

var NoFlagInExpression bool

