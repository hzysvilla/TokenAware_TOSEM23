package datalog

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

const (
	OyenteParallNum       int = 30
	RuntimeCodeChannelNum int = 50000
)

type structRuntimeCode struct {
	Addr string
	Code string
}

var Once sync.Once

var Wg = new(sync.WaitGroup)
var DWg = new(sync.WaitGroup)

var ChRuntimeCodes = make(chan structRuntimeCode, RuntimeCodeChannelNum)

var ContractToTxHash sync.Map

var OyenteResults sync.Map          // TxHash or Addr ==> result
var OyenteCacheResults sync.Map     // add by zws. hash(runtimecode) ==> result
var OyenteCacheVisitedFlag sync.Map //add by hzy. hash(runtime) ==>visited flag
// var TxToContract sync.Map       // for pre_exec oyente
var Addr2OyenteFlag sync.Map // flag true when the addr_code was added to RuntimeCodes

func AddRuntimeCodeOnAfterDownload(txHash string, RuntimeBytecode string) {
	var runtimeCode structRuntimeCode
	runtimeCode.Addr = txHash
	runtimeCode.Code = RuntimeBytecode
	//ChRuntimeCodes <- runtimeCode
}

func AddRuntimeCodeDurTxExec(address string, RuntimeBytecode string) {
	var runtimeCode structRuntimeCode
	runtimeCode.Addr = address
	if RuntimeBytecode != "" {
		runtimeCode.Code = RuntimeBytecode
	} else {
		runtimeCode.Code = "6060"
	}
	// ChRuntimeCodes <- runtimeCode
}

func StartOyente() {
	// 添加异常捕获，不让异常直接中断程序
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
	}()
	fmt.Println("hzysdebuginfo threadnum:", OyenteParallNum)
	for i := 0; i < OyenteParallNum; i++ {
		FileName := "tempfile" + strconv.Itoa(i)
		//_ = FileName
		go Con_ExecOyente(FileName)
		//time.Sleep(time.Millisecond*1)
	}
}

func Con_ExecOyente(paraFileName string) {
	for {
		runtimeCode := <-ChRuntimeCodes
		Wg.Add(1)
		ExecOyente(paraFileName, runtimeCode)
		time.Sleep(time.Millisecond * 1)
	}
}

func ExecOyente(key string, runtimecode structRuntimeCode) {
	//fmt.Println("hzysDebugInfo.ExecOyente() Entry","Start process runtime code")
	// defer Wg.Done()
	// //add by hzy
	// //to exclude the vyper bytecode
	// if strings.Contains(runtimecode.Code, VyperSig) == true {
	// 	runtimecode.Code = "6060"
	// }
	// //add end
	// content := []byte(runtimecode.Code)
	// //cachekey := sha256.Sum256(content)
	// hasher := adler32.New()
	// hasher.Write(content)
	// cachekey := hasher.Sum32()

	// var output string
	// CountResult.addOyenteExecCount()
	// if res, ok := OyenteCacheResults.Load(cachekey); ok {
	// 	// get cache
	// 	i := 0
	// 	for i = 0; i <= 6*1e4; i++ {
	// 		res, _ = OyenteCacheResults.Load(cachekey)
	// 		output = fmt.Sprintf("%v", res)
	// 		if output != "locked" {
	// 			break
	// 		} else {
	// 			time.Sleep(time.Millisecond)
	// 		}
	// 	}
	// 	if i == 6*1e4+1 {
	// 		if output == "locked" {
	// 			output = ""
	// 		}
	// 		fmt.Println("hzysdebuginfo", "deadlocked")
	// 	}
	// 	CountResult.addOyenteCacheCount()
	// } else {
	// 	OyenteCacheResults.Store(cachekey, "locked")
	// 	// not get cache , add res to cache
	// 	filename := key
	// 	codepath := BytecodePath + filename
	// 	err := ioutil.WriteFile(codepath, content, 0666)
	// 	if err != nil {
	// 		fmt.Println("[oyente] ioutil WriteFile error")
	// 	}
	// 	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	// 	defer cancel()

	// 	cmd := exec.CommandContext(ctx, "python2", OyentePath, "-s", codepath, "-b")
	// 	out, err := cmd.Output()
	// 	if err != nil {
	// 		log.Error("[oyente exec err]:", "error TxAddr", runtimecode.Addr)
	// 	}
	// 	if ctx.Err() == context.DeadlineExceeded {
	// 		fmt.Println("Command timed out")
	// 		fmt.Println("timeout addr: ", runtimecode.Addr)
	// 		OyenteResults.Store(runtimecode.Addr, output)
	// 		return
	// 	}
	// 	output = string(out[:])
	// 	OyenteCacheResults.Store(cachekey, output)
	// }
	// //fmt.Println("[oyente] routine get oyente result:", runtimecode.Addr, "=>", output)
	// OyenteResults.Store(runtimecode.Addr, output)
	//SaveToDb(runtimecode.Addr, output, OyenteResultsDb)
	//fmt.Println("OyenteExec.go ,Get Contract bytecode.\nContract Addr:",runtimecode.Addr,"\nresult:",output)
	//增加tokenContractCount的计数
	// if strings.Contains(output, "sha3(") {
	// 	//tempCount := <-tokenContractCount
	// 	//tempCount++
	// 	//tokenContractCount <- tempCount
	// 	CountResult.addTokenCount()
	// }
	return
}

func WaitOyenteRes(addr string) string {
	//fmt.Println("hzysDebugInfo","datalog.WaitOyenteRes entry")
	defer TimeTrack(time.Now(), &TotalWaitTime)
	var WaitTime int = 1 //wait 60 seconds
	res := ""
	var i = 0
	//var ContractAddrFlag bool
	if re, ok := Addr2OyenteFlag.Load(addr); ok && re.(bool) == true {
		//ContractAddrFlag=true
		for i = 0; i < WaitTime; i++ { // 等待不超过WaitTime秒
			// if tempres, hasResult := OyenteResults.Load(addr); hasResult {
			// 	//  fmt.Println("contract addr has oyente result!")
			// 	res = tempres.(string)
			// 	break
			// }
			break
			if i == WaitTime-1 {
				//fmt.Println("addr: ", addr, "has waited for no oyente result")
				//log.Warn("oyente process timeout", "the tx addr=", addr)
				_ = 1
			}
			time.Sleep(time.Millisecond * 1) //睡眠1毫秒让运行oyente的协程有机会写OyenteResults
		}
	} else if re, ok := ContractToTxHash.Load(addr); ok {
		_ = re
		//ContractAddrFlag=true
		//fmt.Println("HHHHHHHHHHHHHHHHHHHHHHHHHH")
		for i = 0; i < WaitTime; i++ { // 等待不超过60秒
			// if tempres, hasResult := OyenteResults.Load(re); hasResult {
			// 	//  fmt.Println("contract addr has oyente result!")  by zws
			// 	res = tempres.(string)
			// 	break
			// }
			break
			if i == WaitTime-1 {
				//fmt.Println("addr: ", addr, "has waited for no oyente result")
				_ = 1
			}
			time.Sleep(time.Millisecond * 100) //睡眠1毫秒让运行oyente的协程有机会写OyenteResults by zws
		}
	}
	/*	if ContractAddrFlag {
		if _, checked := ContractCheckFlag[addr]; !checked {
			ContractCheckFlag[addr] = struct{}{}
			ContractWaitCounter[i] += 1
		} else {
			if i != 0 {
				fmt.Println("waitcheck error")
			}
		}
	}*/
	/*	if i>0{
		CountResult.addWaitContractCount()
	}*/
	//fmt.Println("hzysDebugInfo","datalog.WaitOyenteRes end","\nres",res)
	return res
}
