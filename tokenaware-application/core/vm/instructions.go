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

package vm

import (
	"errors"
	"math/big"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/crypto/sha3"
	"strings"
	"strconv"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/datalog"
	"time"
)

var (
	bigZero                  = new(big.Int)
	tt255                    = math.BigPow(2, 255)
	errWriteProtection       = errors.New("evm: write protection")
	errReturnDataOutOfBounds = errors.New("evm: return data out of bounds")
	errExecutionReverted     = errors.New("evm: execution reverted")
	errMaxCodeSizeExceeded   = errors.New("evm: max code size exceeded")
	errInvalidJump           = errors.New("evm: invalid jump destination")
)

func opAdd(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	// zws
	StartTime:=time.Now()
	if interpreter.evm.IsTxStart() && interpreter.evm.opactive["ADD"] {
		x_byte32 := common.BigToHash(x)
		y_byte32 := common.BigToHash(y)
		var re = new(big.Int).Set(y)
		re.Add(x, re)
		re_byte32 := common.BigToHash(re)
		//fmt.Println(" \nop ADD : x:",x_byte32.String(),"\ny:",y_byte32.String())
		if addr_xstr, ok := interpreter.evm.loc2addr[x_byte32]; ok && x.Cmp(bigZero) != 0 {
			//fmt.Println("n \nop ADD : map xloc:",x_byte32.String(),"\naddr:",addr_xstr)
			interpreter.evm.loc2addr[re_byte32] = addr_xstr
		}
		if addr_ystr, ok := interpreter.evm.loc2addr[y_byte32]; ok && y.Cmp(bigZero) != 0 {
			//fmt.Println("\nop ADD : map yloc:",y_byte32.String(),"\naddr:",addr_ystr)
			interpreter.evm.loc2addr[re_byte32] = addr_ystr
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)


	math.U256(y.Add(x, y))

	interpreter.intPool.put(x)
	return nil, nil
}

func opSub(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	// zws
	StartTime:=time.Now()
	if interpreter.evm.IsTxStart() && interpreter.evm.opactive["SUB"] {
		x_byte32 := common.BigToHash(x)
		y_byte32 := common.BigToHash(y)
		var re = new(big.Int).Set(y)
		re.Sub(x, re)
		re_byte32 := common.BigToHash(re)

		if addr_xstr, ok := interpreter.evm.loc2addr[x_byte32]; ok && x.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_xstr
		}
		if addr_ystr, ok := interpreter.evm.loc2addr[y_byte32]; ok && y.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_ystr
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)


	math.U256(y.Sub(x, y))

	interpreter.intPool.put(x)
	return nil, nil
}

func opMul(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.pop()

	// zws
	StartTime:= time.Now()
	if interpreter.evm.IsTxStart() && interpreter.evm.opactive["MUL"] {
		x_byte32 := common.BigToHash(x)
		y_byte32 := common.BigToHash(y)
		var re = new(big.Int).Set(y)
		re.Mul(x, re)
		re_byte32 := common.BigToHash(re)

		if addr_xstr, ok := interpreter.evm.loc2addr[x_byte32]; ok && x.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_xstr
		}
		if addr_ystr, ok := interpreter.evm.loc2addr[y_byte32]; ok && y.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_ystr
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)


	stack.push(math.U256(x.Mul(x, y)))

	interpreter.intPool.put(y)

	return nil, nil
}

func opDiv(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	// zws
	StartTime:= time.Now()
	if interpreter.evm.IsTxStart() && interpreter.evm.opactive["DIV"] {
		x_byte32 := common.BigToHash(x)
		y_byte32 := common.BigToHash(y)
		var re = new(big.Int).Set(y)
		if re.Sign() != 0 {
			re.Div(x, re)
		} else {
			re.SetUint64(0)
		}
		
		re_byte32 := common.BigToHash(re)

		if addr_xstr, ok := interpreter.evm.loc2addr[x_byte32]; ok && x.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_xstr
		}
		if addr_ystr, ok := interpreter.evm.loc2addr[y_byte32]; ok && y.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_ystr
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)


	if y.Sign() != 0 {
		math.U256(y.Div(x, y))
	} else {
		y.SetUint64(0)
	}
	interpreter.intPool.put(x)
	return nil, nil
}

func opSdiv(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := math.S256(stack.pop()), math.S256(stack.pop())
	res := interpreter.intPool.getZero()

	if y.Sign() == 0 || x.Sign() == 0 {
		stack.push(res)
	} else {
		if x.Sign() != y.Sign() {
			res.Div(x.Abs(x), y.Abs(y))
			res.Neg(res)
		} else {
			res.Div(x.Abs(x), y.Abs(y))
		}
		stack.push(math.U256(res))
	}
	interpreter.intPool.put(x, y)
	return nil, nil
}

func opMod(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.pop()
	if y.Sign() == 0 {
		stack.push(x.SetUint64(0))
	} else {
		stack.push(math.U256(x.Mod(x, y)))
	}
	interpreter.intPool.put(y)
	return nil, nil
}

func opSmod(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := math.S256(stack.pop()), math.S256(stack.pop())
	res := interpreter.intPool.getZero()

	if y.Sign() == 0 {
		stack.push(res)
	} else {
		if x.Sign() < 0 {
			res.Mod(x.Abs(x), y.Abs(y))
			res.Neg(res)
		} else {
			res.Mod(x.Abs(x), y.Abs(y))
		}
		stack.push(math.U256(res))
	}
	interpreter.intPool.put(x, y)
	return nil, nil
}

func opExp(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	base, exponent := stack.pop(), stack.pop()
	// some shortcuts
	cmpToOne := exponent.Cmp(big1)
	if cmpToOne < 0 { // Exponent is zero
		// x ^ 0 == 1
		stack.push(base.SetUint64(1))
	} else if base.Sign() == 0 {
		// 0 ^ y, if y != 0, == 0
		stack.push(base.SetUint64(0))
	} else if cmpToOne == 0 { // Exponent is one
		// x ^ 1 == x
		stack.push(base)
	} else {
		stack.push(math.Exp(base, exponent))
		interpreter.intPool.put(base)
	}
	interpreter.intPool.put(exponent)
	return nil, nil
}

func opSignExtend(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	back := stack.pop()
	if back.Cmp(big.NewInt(31)) < 0 {
		bit := uint(back.Uint64()*8 + 7)
		num := stack.pop()
		mask := back.Lsh(common.Big1, bit)
		mask.Sub(mask, common.Big1)
		if num.Bit(int(bit)) > 0 {
			num.Or(num, mask.Not(mask))
		} else {
			num.And(num, mask)
		}

		stack.push(math.U256(num))
	}

	interpreter.intPool.put(back)
	return nil, nil
}

func opNot(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x := stack.peek()
	math.U256(x.Not(x))
	return nil, nil
}

func opLt(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	if x.Cmp(y) < 0 {
		y.SetUint64(1)
	} else {
		y.SetUint64(0)
	}
	interpreter.intPool.put(x)
	return nil, nil
}

func opGt(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	if x.Cmp(y) > 0 {
		y.SetUint64(1)
	} else {
		y.SetUint64(0)
	}
	interpreter.intPool.put(x)
	return nil, nil
}

func opSlt(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	xSign := x.Cmp(tt255)
	ySign := y.Cmp(tt255)

	switch {
	case xSign >= 0 && ySign < 0:
		y.SetUint64(1)

	case xSign < 0 && ySign >= 0:
		y.SetUint64(0)

	default:
		if x.Cmp(y) < 0 {
			y.SetUint64(1)
		} else {
			y.SetUint64(0)
		}
	}
	interpreter.intPool.put(x)
	return nil, nil
}

func opSgt(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	xSign := x.Cmp(tt255)
	ySign := y.Cmp(tt255)

	switch {
	case xSign >= 0 && ySign < 0:
		y.SetUint64(0)

	case xSign < 0 && ySign >= 0:
		y.SetUint64(1)

	default:
		if x.Cmp(y) > 0 {
			y.SetUint64(1)
		} else {
			y.SetUint64(0)
		}
	}
	interpreter.intPool.put(x)
	return nil, nil
}

func opEq(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	if x.Cmp(y) == 0 {
		y.SetUint64(1)
	} else {
		y.SetUint64(0)
	}
	interpreter.intPool.put(x)
	return nil, nil
}

func opIszero(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x := stack.peek()
	if x.Sign() > 0 {
		x.SetUint64(0)
	} else {
		x.SetUint64(1)
	}
	return nil, nil
}

func opAnd(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.pop()

	// zws
	StartTime:=time.Now()
	if interpreter.evm.IsTxStart() && interpreter.evm.PatternExistFlag {
		address_mask, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffff", 16)
		if x.Cmp(address_mask) == 0 {
			var temp_y = new(big.Int).Set(y)
			temp_y.And(x, temp_y)
			addr_str := common.BytesToAddress(temp_y.Bytes()).String()
			loc_b32 := common.BigToHash(temp_y)
			//fmt.Println("\nand : map loc:",loc_b32.String(),"\naddr:",addr_str)
			interpreter.evm.loc2addr[loc_b32] = addr_str

			// fmt.Println("AND LOC: ", loc_b32)
		//	 fmt.Println("AND ADDR: ", addr_str)

		} else if y.Cmp(address_mask) == 0 {
			var temp_x = new(big.Int).Set(x)
			temp_x.And(temp_x, y)
			addr_str := common.BytesToAddress(temp_x.Bytes()).String()
			loc_b32 := common.BigToHash(temp_x)
			//fmt.Println("hzysDebugInfo\nand  : map loc:",loc_b32.String(),"\naddr:",addr_str)
			interpreter.evm.loc2addr[loc_b32] = addr_str

			//fmt.Println("AND LOC: ", loc_b32)
			//fmt.Println("AND ADDR: ", addr_str)
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)


	stack.push(x.And(x, y))

	interpreter.intPool.put(y)
	return nil, nil
}

func opOr(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	// zws
	StartTime:=time.Now()
	if interpreter.evm.PatternExistFlag&&interpreter.evm.IsTxStart() && interpreter.evm.opactive["OR"] {
		x_byte32 := common.BigToHash(x)
		y_byte32 := common.BigToHash(y)
		var re = new(big.Int).Set(y)
		re.Or(x, re)
		re_byte32 := common.BigToHash(re)

		if addr_xstr, ok := interpreter.evm.loc2addr[x_byte32]; ok && x.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_xstr
		}
		if addr_ystr, ok := interpreter.evm.loc2addr[y_byte32]; ok && y.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_ystr
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)


	y.Or(x, y)

	interpreter.intPool.put(x)
	return nil, nil
}

func opXor(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	// zws
	StartTime:=time.Now()
	if interpreter.evm.PatternExistFlag&&interpreter.evm.IsTxStart() && interpreter.evm.opactive["XOR"] {
		x_byte32 := common.BigToHash(x)
		y_byte32 := common.BigToHash(y)
		var re = new(big.Int).Set(y)
		re.Xor(x, re)
		re_byte32 := common.BigToHash(re)

		if addr_xstr, ok := interpreter.evm.loc2addr[x_byte32]; ok && x.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_xstr
		}
		if addr_ystr, ok := interpreter.evm.loc2addr[y_byte32]; ok && y.Cmp(bigZero) != 0 {
			interpreter.evm.loc2addr[re_byte32] = addr_ystr
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)


	y.Xor(x, y)

	interpreter.intPool.put(x)
	return nil, nil
}

func opByte(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	th, val := stack.pop(), stack.peek()
	if th.Cmp(common.Big32) < 0 {
		b := math.Byte(val, 32, int(th.Int64()))
		val.SetUint64(uint64(b))
	} else {
		val.SetUint64(0)
	}
	interpreter.intPool.put(th)
	return nil, nil
}

func opAddmod(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y, z := stack.pop(), stack.pop(), stack.pop()
	if z.Cmp(bigZero) > 0 {
		x.Add(x, y)
		x.Mod(x, z)
		stack.push(math.U256(x))
	} else {
		stack.push(x.SetUint64(0))
	}
	interpreter.intPool.put(y, z)
	return nil, nil
}

func opMulmod(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y, z := stack.pop(), stack.pop(), stack.pop()
	if z.Cmp(bigZero) > 0 {
		x.Mul(x, y)
		x.Mod(x, z)
		stack.push(math.U256(x))
	} else {
		stack.push(x.SetUint64(0))
	}
	interpreter.intPool.put(y, z)
	return nil, nil
}

// opSHL implements Shift Left
// The SHL instruction (shift left) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the left by arg1 number of bits.
func opSHL(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := math.U256(stack.pop()), math.U256(stack.peek())
	defer interpreter.intPool.put(shift) // First operand back into the pool

	if shift.Cmp(common.Big256) >= 0 {
		value.SetUint64(0)
		return nil, nil
	}
	n := uint(shift.Uint64())
	math.U256(value.Lsh(value, n))

	return nil, nil
}

// opSHR implements Logical Shift Right
// The SHR instruction (logical shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with zero fill.
func opSHR(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := math.U256(stack.pop()), math.U256(stack.peek())
	defer interpreter.intPool.put(shift) // First operand back into the pool

	if shift.Cmp(common.Big256) >= 0 {
		value.SetUint64(0)
		return nil, nil
	}
	n := uint(shift.Uint64())
	math.U256(value.Rsh(value, n))

	return nil, nil
}

// opSAR implements Arithmetic Shift Right
// The SAR instruction (arithmetic shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with sign extension.
func opSAR(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Note, S256 returns (potentially) a new bigint, so we're popping, not peeking this one
	shift, value := math.U256(stack.pop()), math.S256(stack.pop())
	defer interpreter.intPool.put(shift) // First operand back into the pool

	if shift.Cmp(common.Big256) >= 0 {
		if value.Sign() >= 0 {
			value.SetUint64(0)
		} else {
			value.SetInt64(-1)
		}
		stack.push(math.U256(value))
		return nil, nil
	}
	n := uint(shift.Uint64())
	value.Rsh(value, n)
	stack.push(math.U256(value))

	return nil, nil
}

func opSha3(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset, size := stack.pop(), stack.pop()
	data := memory.GetPtr(offset.Int64(), size.Int64())

	if interpreter.hasher == nil {
		interpreter.hasher = sha3.NewLegacyKeccak256().(keccakState)
	} else {
		interpreter.hasher.Reset()
	}
	interpreter.hasher.Write(data)
	interpreter.hasher.Read(interpreter.hasherBuf[:])

	evm := interpreter.evm
	if evm.vmConfig.EnablePreimageRecording {
		evm.StateDB.AddPreimage(interpreter.hasherBuf, data)
	}
	stack.push(interpreter.intPool.get().SetBytes(interpreter.hasherBuf[:]))
    //fmt.Println("\nSHA3 external")
	//fmt.Println( "the loc of sha3",strconv.Itoa(int(*pc) + 1),"")
	//fmt.Println("hashbuf:",interpreter.hasherBuf.String(),"data:",common.BytesToHash(data).String(),"raw:",data,"rawlen",len(data))
	// add by zws
	StartTime:=time.Now()
	if interpreter.evm.PatternExistFlag && interpreter.evm.IsTxStart() && interpreter.evm.opactive["SHA3"] {

		loc_byte32 := common.BigToHash(interpreter.intPool.get().SetBytes(interpreter.hasherBuf[:]))
		t_addr_str := "0x0000000000000000000000000000000000000000"
		for i := 0; i+31 < len(data); i += 32 {
			temp := data[i : i+32]
		//	fmt.Println("the original key",common.BytesToHash(temp).String())
			if addr_str := interpreter.evm.loc2addr[common.BytesToHash(temp)]; strings.Compare(addr_str, "") != 0 {
				//fmt.Println(" \nSHA3(internal1) : map loc:",loc_byte32.String(),"\naddr:",addr_str)
				interpreter.evm.loc2addr[loc_byte32] = addr_str
				if strings.Compare(addr_str, "0x0000000000000000000000000000000000000000") != 0 {
					t_addr_str = addr_str
				}
			//	fmt.Println("sha3 result: ", common.BigToHash(interpreter.intPool.get().SetBytes(interpreter.hasherBuf[:])))
			//	fmt.Println("sha3 addr: ", addr_str)
			}
		}
		if strings.Compare(t_addr_str, "0x0000000000000000000000000000000000000000") != 0 {
			//fmt.Println(" SHA3(internal2) : map loc:",loc_byte32.String(),"\naddr:",t_addr_str)
			interpreter.evm.loc2addr[loc_byte32] = t_addr_str
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)

	interpreter.intPool.put(offset, size)
	return nil, nil
}

func opAddress(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().SetBytes(contract.Address().Bytes()))
	return nil, nil
}

func opBalance(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	slot := stack.peek()
	slot.Set(interpreter.evm.StateDB.GetBalance(common.BigToAddress(slot)))
	return nil, nil
}

func opOrigin(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().SetBytes(interpreter.evm.Origin.Bytes()))
	return nil, nil
}

func opCaller(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().SetBytes(contract.Caller().Bytes()))

	// add by zws
	StartTime:=time.Now()
	if interpreter.evm.PatternExistFlag&&interpreter.evm.IsTxStart() {//find msg.sender
		temp_bytes := contract.Caller().Bytes()
		addr_str := contract.Caller().String()
		temp_bytes32 := common.BytesToHash(temp_bytes)
		//fmt.Println("\ncaller  : map loc:",temp_bytes32.String(),"\naddr:",addr_str)
		interpreter.evm.loc2addr[temp_bytes32] = addr_str

	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)
	// for vyper addrRel

	return nil, nil
}

func opCallValue(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().Set(contract.value))
	return nil, nil
}

func opCallDataLoad(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var Calldata=getDataBig(contract.Input, stack.pop(), big32)
	stack.push(interpreter.intPool.get().SetBytes(Calldata))
	//add by hzy on 20-10-6
	//To get the data which is similar to addr
	//fmt.Println("\nCallDataLoad","\nData:",hex.EncodeToString(Calldata))
	StartTime:=time.Now()
	if interpreter.evm.PatternExistFlag&&interpreter.evm.isTxStart {
		var strCallData = hex.EncodeToString(Calldata)
		if strCallData[:24] == "000000000000000000000000" && strCallData[24:62] != "00000000000000000000000000000000000000" {
			//fmt.Println(strCallData[:24],strCallData[24:62])
			AddrBytes := common.BytesToHash(Calldata)
			interpreter.evm.loc2addr[AddrBytes] = "0x" + strCallData[24:]
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)
	//add end
	return nil, nil
}

func opCallDataSize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().SetInt64(int64(len(contract.Input))))
	return nil, nil
}

func opCallDataCopy(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		memOffset  = stack.pop()
		dataOffset = stack.pop()
		length     = stack.pop()
	)
	memory.Set(memOffset.Uint64(), length.Uint64(), getDataBig(contract.Input, dataOffset, length))

	interpreter.intPool.put(memOffset, dataOffset, length)
	return nil, nil
}

func opReturnDataSize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().SetUint64(uint64(len(interpreter.returnData))))
	return nil, nil
}

func opReturnDataCopy(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		memOffset  = stack.pop()
		dataOffset = stack.pop()
		length     = stack.pop()

		end = interpreter.intPool.get().Add(dataOffset, length)
	)
	defer interpreter.intPool.put(memOffset, dataOffset, length, end)

	if !end.IsUint64() || uint64(len(interpreter.returnData)) < end.Uint64() {
		return nil, errReturnDataOutOfBounds
	}
	memory.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnData[dataOffset.Uint64():end.Uint64()])

	return nil, nil
}

func opExtCodeSize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	slot := stack.peek()
	slot.SetUint64(uint64(interpreter.evm.StateDB.GetCodeSize(common.BigToAddress(slot))))

	return nil, nil
}

func opCodeSize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	l := interpreter.intPool.get().SetInt64(int64(len(contract.Code)))
	stack.push(l)

	return nil, nil
}

func opCodeCopy(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)
	codeCopy := getDataBig(contract.Code, codeOffset, length)
	memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	interpreter.intPool.put(memOffset, codeOffset, length)
	return nil, nil
}

func opExtCodeCopy(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		addr       = common.BigToAddress(stack.pop())
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)
	codeCopy := getDataBig(interpreter.evm.StateDB.GetCode(addr), codeOffset, length)
	memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	interpreter.intPool.put(memOffset, codeOffset, length)
	return nil, nil
}

// opExtCodeHash returns the code hash of a specified account.
// There are several cases when the function is called, while we can relay everything
// to `state.GetCodeHash` function to ensure the correctness.
//   (1) Caller tries to get the code hash of a normal contract account, state
// should return the relative code hash and set it as the result.
//
//   (2) Caller tries to get the code hash of a non-existent account, state should
// return common.Hash{} and zero will be set as the result.
//
//   (3) Caller tries to get the code hash for an account without contract code,
// state should return emptyCodeHash(0xc5d246...) as the result.
//
//   (4) Caller tries to get the code hash of a precompiled account, the result
// should be zero or emptyCodeHash.
//
// It is worth noting that in order to avoid unnecessary create and clean,
// all precompile accounts on mainnet have been transferred 1 wei, so the return
// here should be emptyCodeHash.
// If the precompile account is not transferred any amount on a private or
// customized chain, the return value will be zero.
//
//   (5) Caller tries to get the code hash for an account which is marked as suicided
// in the current transaction, the code hash of this account should be returned.
//
//   (6) Caller tries to get the code hash for an account which is marked as deleted,
// this account should be regarded as a non-existent account and zero should be returned.
func opExtCodeHash(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	slot := stack.peek()
	address := common.BigToAddress(slot)
	if interpreter.evm.StateDB.Empty(address) {
		slot.SetUint64(0)
	} else {
		slot.SetBytes(interpreter.evm.StateDB.GetCodeHash(address).Bytes())
	}
	return nil, nil
}

func opGasprice(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().Set(interpreter.evm.GasPrice))
	return nil, nil
}

func opBlockhash(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	num := stack.pop()

	n := interpreter.intPool.get().Sub(interpreter.evm.BlockNumber, common.Big257)
	if num.Cmp(n) > 0 && num.Cmp(interpreter.evm.BlockNumber) < 0 {
		stack.push(interpreter.evm.GetHash(num.Uint64()).Big())
	} else {
		stack.push(interpreter.intPool.getZero())
	}
	interpreter.intPool.put(num, n)
	return nil, nil
}

func opCoinbase(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().SetBytes(interpreter.evm.Coinbase.Bytes()))
	return nil, nil
}

func opTimestamp(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(math.U256(interpreter.intPool.get().Set(interpreter.evm.Time)))
	return nil, nil
}

func opNumber(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(math.U256(interpreter.intPool.get().Set(interpreter.evm.BlockNumber)))
	return nil, nil
}

func opDifficulty(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(math.U256(interpreter.intPool.get().Set(interpreter.evm.Difficulty)))
	return nil, nil
}

func opGasLimit(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(math.U256(interpreter.intPool.get().SetUint64(interpreter.evm.GasLimit)))
	return nil, nil
}

func opPop(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	interpreter.intPool.put(stack.pop())
	return nil, nil
}

func opMload(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	v := stack.peek()
	offset := v.Int64()
	v.SetBytes(memory.GetPtr(offset, 32))
	return nil, nil
}

func opMstore(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// pop value of the stack
	mStart, val := stack.pop(), stack.pop()

	// zws
	StartTime:=time.Now()
	if interpreter.evm.PatternExistFlag && interpreter.evm.IsTxStart() && interpreter.evm.opactive["CALLER"] {//vyper
		temp_b32 := common.BigToHash(val)
		temp_addr := common.BigToAddress(val).String()
		for _, funinfos := range datalog.FunInfos {//vyper use call function addr examnation
			if strings.Compare(funinfos.AccTo, temp_addr) == 0 {
				interpreter.evm.loc2addr[temp_b32] = temp_addr
			}
		}

	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)
	memory.Set32(mStart.Uint64(), val)
	interpreter.intPool.put(mStart, val)
	return nil, nil
}

func opMstore8(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	off, val := stack.pop().Int64(), stack.pop().Int64()
	memory.store[off] = byte(val & 0xff)

	return nil, nil
}

func opSload(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	loc := stack.peek()
	val := interpreter.evm.StateDB.GetState(contract.Address(), common.BigToHash(loc))
	//fmt.Println("\nexternal \nSload : map loc:",common.BigToHash(loc).String(),"\naddr:",val.String())
	// add by zws
	StartTime:=time.Now()
	if interpreter.evm.PatternExistFlag && interpreter.evm.IsTxStart() {

		temploc := common.BigToHash(loc)
		var tempval = new(big.Int).Set(val.Big())
		if _, ok := interpreter.evm.sloadloc2val[temploc]; !ok {//get the first load value
		//	fmt.Println("internal1 \nSload : map loc:",temploc.String(),"\naddr:",tempval.String())
			interpreter.evm.sloadloc2val[temploc] = tempval
		}

		if addr, ok := interpreter.evm.loc2addr[temploc]; ok  {
			//fmt.Println("internal2 \nSload : map loc:",temploc.String(),"\naddr:",addr)
			interpreter.evm.loc2addr[common.BigToHash(tempval)] = addr
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)
	//

	loc.SetBytes(val.Bytes())
	return nil, nil
}

func opSstore(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	loc := common.BigToHash(stack.pop())
	val := stack.pop()
	// add by zws\
	StartTime:=time.Now()
	if interpreter.evm.PatternExistFlag && interpreter.evm.IsTxStart() {
		temploc := loc
		var tempval = new(big.Int).Set(val)
		pc_addr := strconv.Itoa(int(*pc) + 1)
		pc_addr = pc_addr + interpreter.evm.curcalladdr
		//fmt.Println("\nSstore(external) : map loc:",temploc.String(),"\naddr:",tempval.String())
		//fmt.Println("\nsstore",pc_addr)
		if pattern, ok := interpreter.evm.pc2pattern[pc_addr]; ok {
			if account, ok := interpreter.evm.loc2addr[temploc]; ok {
				//fmt.Println("Sstore(Internal)","hit in sstoredebug")
				changeval := tempval
				var loc2 = new(big.Int).Set(loc.Big())
				var one = new(big.Int).SetUint64(1)
				loc2.Sub(loc2, one)
				temploc2 := common.BigToHash(loc2)
				if interpreter.evm.valueoffset == 0 {
					if sloadval, ok := interpreter.evm.sloadloc2val[temploc]; ok {
						changeval = tempval.Sub(tempval, sloadval)
					} else if sloadval, ok := interpreter.evm.sloadloc2val[temploc2]; ok {
						changeval = tempval.Sub(tempval, sloadval)
					}
				} else if interpreter.evm.valueoffset == 128 {
					var tempsloadval = new(big.Int).SetUint64(0)
					if sloadval, ok := interpreter.evm.sloadloc2val[temploc2]; ok  {
						tempsloadval.Set(sloadval)
					} else if sloadval, ok := interpreter.evm.sloadloc2val[temploc]; ok  {
						tempsloadval.Set(sloadval)
					}
					beforeval := math.U256(tempsloadval)
					afterval := math.U256(tempval)
					math.U256(beforeval.Rsh(beforeval, 128))
					math.U256(afterval.Rsh(afterval, 128))
					changeval.Sub(afterval, beforeval)
				}
				var tempCoreData datalog.CoreData
				tempCoreData.Account = account//EOA
				tempCoreData.Val = changeval//Value
				tempCoreData.Pattern = pattern //Pattern
				tempCoreData.ConAddr = interpreter.evm.curcalladdr//ContractAddr
				tempCoreData.CallLayer = interpreter.evm.call_layer//CallLayer
				sstorekey := interpreter.evm.curcalladdr + temploc.String()//storageAddr
				datalog.SStoreLoc2CoreData[sstorekey] = tempCoreData
			}
		}
	}
	datalog.TimeTrack(StartTime, &datalog.TotalConcolicExecTime)
	interpreter.evm.StateDB.SetState(contract.Address(), loc, common.BigToHash(val))
	interpreter.intPool.put(val)
	return nil, nil
}

func opJump(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	pos := stack.pop()
	if !contract.validJumpdest(pos) {
		return nil, errInvalidJump
	}
	*pc = pos.Uint64()

	interpreter.intPool.put(pos)
	return nil, nil
}

func opJumpi(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	pos, cond := stack.pop(), stack.pop()
	if cond.Sign() != 0 {
		if !contract.validJumpdest(pos) {
			return nil, errInvalidJump
		}
		*pc = pos.Uint64()
	} else {
		*pc++
	}

	interpreter.intPool.put(pos, cond)
	return nil, nil
}

func opJumpdest(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, nil
}

func opPc(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().SetUint64(*pc))
	return nil, nil
}

func opMsize(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().SetInt64(int64(memory.Len())))
	return nil, nil
}

func opGas(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(interpreter.intPool.get().SetUint64(contract.Gas))
	return nil, nil
}

func opCreate(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		value        = stack.pop()
		offset, size = stack.pop(), stack.pop()
		input        = memory.GetCopy(offset.Int64(), size.Int64())
		gas          = contract.Gas
	)
	if interpreter.evm.chainRules.IsEIP150 {
		gas -= gas / 64
	}

	contract.UseGas(gas)
	res, addr, returnGas, suberr := interpreter.evm.Create(contract, input, gas, value)
	// Push item on the stack based on the returned error. If the ruleset is
	// homestead we must check for CodeStoreOutOfGasError (homestead only
	// rule) and treat as an error, if the ruleset is frontier we must
	// ignore this error and pretend the operation was successful.
	if interpreter.evm.chainRules.IsHomestead && suberr == ErrCodeStoreOutOfGas {
		stack.push(interpreter.intPool.getZero())
	} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
		stack.push(interpreter.intPool.getZero())
	} else {
		stack.push(interpreter.intPool.get().SetBytes(addr.Bytes()))
	}
	contract.Gas += returnGas
	interpreter.intPool.put(value, offset, size)

	if suberr == errExecutionReverted {
		return res, nil
	}

	// add by zws
	if interpreter.evm.IsTxStart() {
		datalog.DWg.Add(1)
		go func() {
		   // StartTime:=time.Now()
			con_addr := addr.String()
			con_code := hex.EncodeToString(res)
			datalog.Addr2OyenteFlag.Store(con_addr, true)
			datalog.AddRuntimeCodeDurTxExec(con_addr, con_code)
			//datalog.TimeTrack(StartTime, &datalog.TotalProcTime)
			datalog.DWg.Done()
		}()
	}
	//end

	return nil, nil
}

func opCreate2(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		endowment    = stack.pop()
		offset, size = stack.pop(), stack.pop()
		salt         = stack.pop()
		input        = memory.GetCopy(offset.Int64(), size.Int64())
		gas          = contract.Gas
	)

	// Apply EIP150
	gas -= gas / 64
	contract.UseGas(gas)
	res, addr, returnGas, suberr := interpreter.evm.Create2(contract, input, gas, endowment, salt)
	// Push item on the stack based on the returned error.
	if suberr != nil {
		stack.push(interpreter.intPool.getZero())
	} else {
		stack.push(interpreter.intPool.get().SetBytes(addr.Bytes()))
	}
	contract.Gas += returnGas
	interpreter.intPool.put(endowment, offset, size, salt)

	if suberr == errExecutionReverted {
		return res, nil
	}

	// add by zws
	if interpreter.evm.IsTxStart() {
		datalog.DWg.Add(1)
		go func() {
			//StartTime:=time.Now()
			con_addr := addr.String()
			con_code := hex.EncodeToString(res)
			datalog.Addr2OyenteFlag.Store(con_addr, true)
			datalog.AddRuntimeCodeDurTxExec(con_addr, con_code)
			//datalog.TimeTrack(StartTime, &datalog.TotalProcTime)
			datalog.DWg.Done ()
		}()
	}
	//end

	return nil, nil
}

func opCall(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Pop gas. The actual gas in interpreter.evm.callGasTemp.
	interpreter.intPool.put(stack.pop())
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.BigToAddress(addr)
	value = math.U256(value)
	// Get the arguments from the memory.
	args := memory.GetPtr(inOffset.Int64(), inSize.Int64())

	if value.Sign() != 0 {
		gas += params.CallStipend
	}
	ret, returnGas, err := interpreter.evm.Call(contract, toAddr, args, gas, value)
	if err != nil {
		stack.push(interpreter.intPool.getZero())
	} else {
		stack.push(interpreter.intPool.get().SetUint64(1))
	}
	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	contract.Gas += returnGas

	interpreter.intPool.put(addr, value, inOffset, inSize, retOffset, retSize)
	return ret, nil
}

func opCallCode(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	interpreter.intPool.put(stack.pop())
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.BigToAddress(addr)
	value = math.U256(value)
	// Get arguments from the memory.
	args := memory.GetPtr(inOffset.Int64(), inSize.Int64())

	if value.Sign() != 0 {
		gas += params.CallStipend
	}
	ret, returnGas, err := interpreter.evm.CallCode(contract, toAddr, args, gas, value)
	if err != nil {
		stack.push(interpreter.intPool.getZero())
	} else {
		stack.push(interpreter.intPool.get().SetUint64(1))
	}
	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	contract.Gas += returnGas

	interpreter.intPool.put(addr, value, inOffset, inSize, retOffset, retSize)
	return ret, nil
}

func opDelegateCall(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	interpreter.intPool.put(stack.pop())
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.BigToAddress(addr)
	// Get arguments from the memory.
	args := memory.GetPtr(inOffset.Int64(), inSize.Int64())

	ret, returnGas, err := interpreter.evm.DelegateCall(contract, toAddr, args, gas)
	if err != nil {
		stack.push(interpreter.intPool.getZero())
	} else {
		stack.push(interpreter.intPool.get().SetUint64(1))
	}
	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	contract.Gas += returnGas

	interpreter.intPool.put(addr, inOffset, inSize, retOffset, retSize)
	return ret, nil
}

func opStaticCall(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	interpreter.intPool.put(stack.pop())
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.BigToAddress(addr)
	// Get arguments from the memory.
	args := memory.GetPtr(inOffset.Int64(), inSize.Int64())

	ret, returnGas, err := interpreter.evm.StaticCall(contract, toAddr, args, gas)
	if err != nil {
		stack.push(interpreter.intPool.getZero())
	} else {
		stack.push(interpreter.intPool.get().SetUint64(1))
	}
	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	contract.Gas += returnGas

	interpreter.intPool.put(addr, inOffset, inSize, retOffset, retSize)
	return ret, nil
}

func opReturn(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset, size := stack.pop(), stack.pop()
	ret := memory.GetPtr(offset.Int64(), size.Int64())

	interpreter.intPool.put(offset, size)
	return ret, nil
}

func opRevert(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset, size := stack.pop(), stack.pop()
	ret := memory.GetPtr(offset.Int64(), size.Int64())

	interpreter.intPool.put(offset, size)
	return ret, nil
}

func opStop(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, nil
}

func opSuicide(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	balance := interpreter.evm.StateDB.GetBalance(contract.Address())
	interpreter.evm.StateDB.AddBalance(common.BigToAddress(stack.pop()), balance)

	interpreter.evm.StateDB.Suicide(contract.Address())
	return nil, nil
}

// following functions are used by the instruction jump  table

// make log instruction function
func makeLog(size int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		topics := make([]common.Hash, size)
		mStart, mSize := stack.pop(), stack.pop()
		for i := 0; i < size; i++ {
			topics[i] = common.BigToHash(stack.pop())
		}

		d := memory.GetCopy(mStart.Int64(), mSize.Int64())
		interpreter.evm.StateDB.AddLog(&types.Log{
			Address: contract.Address(),
			Topics:  topics,
			Data:    d,
			// This is a non-consensus field, but assigned here because
			// core/state doesn't know the current block number.
			BlockNumber: interpreter.evm.BlockNumber.Uint64(),
		})

		// zws
		if interpreter.evm.PatternExistFlag && interpreter.evm.IsTxStart() &&
			size >= 1 &&
			datalog.IsTranferEventSig(topics[0].String()) {
			if size == 3 {
				var event = datalog.TranInfo{
					AccFrom:   common.BytesToAddress(topics[1].Bytes()).String(),
					AccTo:     common.BytesToAddress(topics[2].Bytes()).String(),
					Amount:	   new(big.Int).SetBytes(d),
					ConAddr:   contract.Address().String(),
					FuncName:  "Transfer",
				}
				datalog.EventInfos = append(datalog.EventInfos, event)
			} else if size == 1 {
				from_bytes := d[0:32]
				to_bytes := d[32:64]
				amount_bytes := d[64:96]
				// fmt.Println("EVENT DEBUG: ", mSize.Int64())

				var event = datalog.TranInfo{
					AccFrom:   common.BytesToAddress(from_bytes).String(),
					AccTo:     common.BytesToAddress(to_bytes).String(),
					Amount:    new(big.Int).SetBytes(amount_bytes),
					ConAddr:   contract.Address().String(),
					FuncName:  "Transfer",
				}
				datalog.EventInfos = append(datalog.EventInfos, event)
			} else if size == 4 {
				var event = datalog.TranInfo{
					AccFrom:   common.BytesToAddress(topics[1].Bytes()).String(),
					AccTo:     common.BytesToAddress(topics[2].Bytes()).String(),
					Amount:    new(big.Int).SetBytes(topics[3].Bytes()),
					ConAddr:   contract.Address().String(),
					FuncName:  "Transfer",
				}
				datalog.EventInfos = append(datalog.EventInfos, event)
			}
		}

		interpreter.intPool.put(mStart, mSize)
		return nil, nil
	}
}

// opPush1 is a specialized version of pushN
func opPush1(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		codeLen = uint64(len(contract.Code))
		integer = interpreter.intPool.get()
	)
	*pc += 1
	if *pc < codeLen {
		stack.push(integer.SetUint64(uint64(contract.Code[*pc])))
	} else {
		stack.push(integer.SetUint64(0))
	}
	return nil, nil
}

// make push instruction function
func makePush(size uint64, pushByteSize int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		codeLen := len(contract.Code)

		startMin := codeLen
		if int(*pc+1) < startMin {
			startMin = int(*pc + 1)
		}

		endMin := codeLen
		if startMin+pushByteSize < endMin {
			endMin = startMin + pushByteSize
		}

		integer := interpreter.intPool.get()
		stack.push(integer.SetBytes(common.RightPadBytes(contract.Code[startMin:endMin], pushByteSize)))

		*pc += size
		return nil, nil
	}
}

// make dup instruction function
func makeDup(size int64) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		stack.dup(interpreter.intPool, int(size))
		return nil, nil
	}
}

// make swap instruction function
func makeSwap(size int64) executionFunc {
	// switch n + 1 otherwise n would be swapped with n
	size++
	return func(pc *uint64, interpreter *EVMInterpreter, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		stack.swap(int(size))
		return nil, nil
	}
}
