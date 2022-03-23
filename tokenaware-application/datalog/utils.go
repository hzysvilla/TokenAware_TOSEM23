package datalog

import (
	"os"
	"time"
)

var FindTx bool
var TotalWaitTime time.Duration
var TotalProcTime time.Duration
var TotalAnaTime time.Duration
var TotalConcolicExecTime time.Duration
//var TotalPreWreteTime time.Duration


func TimeTrack(start time.Time, funcTime *time.Duration) {
	elasped := time.Since(start)
	*funcTime += elasped
}

func WriteToFile(content string, path string, isAppend bool) {
	var myErr error
	var f *os.File
	if isAppend {
		f, myErr = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	} else {
		f, myErr = os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	}
	Check(myErr)
	_, writeErr := f.WriteString(content + "\n")
	Check(writeErr)
	err := f.Close()
	Check(err)
}

func Check(err error) {
	if err != nil {
		panic(err)
	}
}