package datalog

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

var CurTxHash string

type CoreDataMatch struct {
	FromFlag bool
	ToFlag   bool
}

func HzysRetWrite() { //write in reult set without match with event and function name
	defer TimeTrack(time.Now(), &TotalAnaTime)
	if IsCapturedCoreData() {
		for _, coredata := range CoreDataArr {
			//fmt.Println("final ret",coredata)
			Ret := "txhash::" + CurTxHash + "::pattern::" + coredata.Pattern + "::ContractAddr::" + coredata.ConAddr
			WriteToFile(Ret, ContractResPath+coredata.ConAddr, true)
		}
	}
}

// add by hzy in 21-3-20
// To find convert Increase in matching the token action value with event log value.
func ConvertIncreaseRetJudge() {
	if IsCapturedCoreData() && IsCapturedEvent() {
		var Con_Pat_Suite = make(map[string]CoreDataMatch) //Contract
		//match the coredata with func and event info
		for _, coredata := range CoreDataArr {
			// fmt.Println("No.", i, ": ", coredata)
			tempkey := coredata.ConAddr + "!!" + coredata.Pattern // something of the Con_Pat_Suite's key
			var tempbig = new(big.Int).SetUint64(0)
			//(ContractAddr+pattern+!!fun+index(in event arrays)+"!!"+func.ConAddr)=>strunct(FromFlag,ToFlag)
			for k, eventdata := range EventInfos {
				if strings.Compare(eventdata.AccFrom, coredata.Account) == 0 &&
					tempbig.Add(eventdata.Amount, coredata.Val).Uint64() == 0 {
					var TempMatch = Con_Pat_Suite[tempkey+"!!event"+strconv.Itoa(k)+"!!"+eventdata.ConAddr]
					TempMatch.FromFlag = true
					Con_Pat_Suite[tempkey+"!!event"+strconv.Itoa(k)+"!!"+eventdata.ConAddr] = TempMatch
					// fmt.Println("From Account Match!!!!")

				}
				if strings.Compare(eventdata.AccTo, coredata.Account) == 0 &&
					eventdata.Amount.Cmp(coredata.Val) == 0 {
					var TempMatch = Con_Pat_Suite[tempkey+"!!event"+strconv.Itoa(k)+"!!"+eventdata.ConAddr]
					TempMatch.ToFlag = true
					Con_Pat_Suite[tempkey+"!!event"+strconv.Itoa(k)+"!!"+eventdata.ConAddr] = TempMatch
					// fmt.Println("To Account Match!!!!")
				}
			}
		}

		for key, val := range Con_Pat_Suite {
			// fmt.Println("key: ", key)
			// fmt.Println("val: ", val)
			if val.FromFlag && val.ToFlag {
				strarr := strings.Split(key, "!!")
				if len(strarr) == 4 {
					conaddr := strarr[0]
					pattern := strarr[1]
					var content string
					content = "txhash::" + CurTxHash + "::pattern::" + pattern + "::matchfor::" + strarr[2] + "::match_addr::" + strarr[3]
					WriteToFile(content, ContractResPath+conaddr, true)
					//fmt.Println("\nhzysDebugInfo\n","ContractAddr:",conaddr,"\nresults:",content,"\n")
				}
			} else if val.FromFlag || val.ToFlag {
				strarr := strings.Split(key, "!!")
				if len(strarr) == 4 {
					conaddr := strarr[0]
					pattern := strarr[1]
					var content string
					content = "txhash::" + CurTxHash + "::pattern::" + pattern + "::match_half_for::" + strarr[2] + "::match_addr::" + strarr[3]
					WriteToFile(content, ContractResPath+conaddr, true)
					//fmt.Println("\nhzysDebugInfo\n","ContractAddr:",conaddr,"\nresults:",content,"\n")
				}
			}
		}

	}
}

func TxConsistAna() { //write in reult set  match with event and function name
	defer TimeTrack(time.Now(), &TotalAnaTime)

	if CurTxHash == DebugTx {
		fmt.Println("debug:", len(App3Info))
	}

	if IsCapturedApp3Info() {
		WriteToFile("tx: "+CurTxHash, "/root/App3Ret", true)

		for _, appinfo := range App3Info {
			WriteToFile("Contract Addr: "+appinfo.ConAddr+"\nFromAddr: "+appinfo.AccFrom+"\nToAddr: "+appinfo.AccTo+"\nAmount: "+appinfo.Amount.String(), "/root/App3Ret", true)
		}

	}

	if IsCapturedCoreData() {
		/*fmt.Println("txhash: ", CurTxHash)
		fmt.Println("func: ", FunInfos)
		fmt.Println("event: ", EventInfos)
		fmt.Println("coredata: ", CoreDataArr)*/

		if IsCapturedFun() || IsCapturedEvent() {
			var Con_Pat_Suite = make(map[string]CoreDataMatch) //Contract
			//match the coredata with func and event info
			for _, coredata := range CoreDataArr {
				var match_flag = false
				// fmt.Println("No.", i, ": ", coredata)
				tempkey := coredata.ConAddr + "!!" + coredata.Pattern // something of the Con_Pat_Suite's key
				var tempbig = new(big.Int).SetUint64(0)
				//(ContractAddr+pattern+!!fun+index+"!!"+func.ConAddr)=>strunct(FromFlag,ToFlag)
				//interface match
				for j, fundata := range FunInfos {
					if strings.Compare(fundata.AccFrom, coredata.Account) == 0 &&
						tempbig.Add(fundata.Amount, coredata.Val).Uint64() == 0 { // the From bookkeeper will record a negative value
						var TempMatch = Con_Pat_Suite[tempkey+"!!fun"+strconv.Itoa(j)+"!!"+fundata.ConAddr] // the Con_Pat_Suite's final key, "j" is the num of funinfo of funinfoarr
						TempMatch.FromFlag = true
						Con_Pat_Suite[tempkey+"!!fun"+strconv.Itoa(j)+"!!"+fundata.ConAddr] = TempMatch
						// fmt.Println("From Account Match!!!!")
						match_flag = true
					}
					if strings.Compare(fundata.AccTo, coredata.Account) == 0 &&
						fundata.Amount.Cmp(coredata.Val) == 0 {
						var TempMatch = Con_Pat_Suite[tempkey+"!!fun"+strconv.Itoa(j)+"!!"+fundata.ConAddr]
						TempMatch.ToFlag = true
						Con_Pat_Suite[tempkey+"!!fun"+strconv.Itoa(j)+"!!"+fundata.ConAddr] = TempMatch
						// fmt.Println("To Account Match!!!!")
						match_flag = true
					}
				}
				//event match
				for k, eventdata := range EventInfos {
					if strings.Compare(eventdata.AccFrom, coredata.Account) == 0 &&
						tempbig.Add(eventdata.Amount, coredata.Val).Uint64() == 0 { // the From bookkeeper will record a negative value
						var TempMatch = Con_Pat_Suite[tempkey+"!!event"+strconv.Itoa(k)+"!!"+eventdata.ConAddr]
						TempMatch.FromFlag = true
						Con_Pat_Suite[tempkey+"!!event"+strconv.Itoa(k)+"!!"+eventdata.ConAddr] = TempMatch
						// fmt.Println("From Account Match!!!!")
						match_flag = true
					}
					if strings.Compare(eventdata.AccTo, coredata.Account) == 0 &&
						eventdata.Amount.Cmp(coredata.Val) == 0 {
						var TempMatch = Con_Pat_Suite[tempkey+"!!event"+strconv.Itoa(k)+"!!"+eventdata.ConAddr]
						TempMatch.ToFlag = true
						Con_Pat_Suite[tempkey+"!!event"+strconv.Itoa(k)+"!!"+eventdata.ConAddr] = TempMatch
						match_flag = true
						// fmt.Println("To Account Match!!!!")
					}
				}
				if match_flag == false {
					content := CurTxHash + "!!" + tempkey
					//WriteToFile(content, "/root/NoneEventFunc", true)
					_ = content
				}

			}

			for key, val := range Con_Pat_Suite {
				// fmt.Println("key: ", key)
				// fmt.Println("val: ", val)
				if val.FromFlag && val.ToFlag {
					strarr := strings.Split(key, "!!")
					if len(strarr) == 4 {
						conaddr := strarr[0]
						pattern := strarr[1]
						var content string
						content = "txhash::" + CurTxHash + "::pattern::" + pattern + "::matchfor::" + strarr[2] + "::match_addr::" + strarr[3]
						_ = conaddr
						_ = content
						//WriteToFile(content, ContractResPath+conaddr, true)
						//fmt.Println("\nhzysDebugInfo\n","ContractAddr:",conaddr,"\nresults:",content,"\n")
					}
				} else if val.FromFlag || val.ToFlag {
					strarr := strings.Split(key, "!!")
					if len(strarr) == 4 {
						conaddr := strarr[0]
						pattern := strarr[1]
						var content string
						content = "txhash::" + CurTxHash + "::pattern::" + pattern + "::match_half_for::" + strarr[2] + "::match_addr::" + strarr[3]
						_ = conaddr
						_ = content
						//WriteToFile(content, ContractResPath+conaddr, true)
						//fmt.Println("\nhzysDebugInfo\n","ContractAddr:",conaddr,"\nresults:",content,"\n")
					}
				}
			}
		} else {

		}
		// var content string
		// content = txhash + " (" + strconv.Itoa(funflag) + "," + strconv.Itoa(eveflag) + "," + strconv.Itoa(coreflag) + ")" + "##" + pattern
		// WriteToFile(content, ContractResPath+filename, true)
	}
}
