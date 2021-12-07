package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	var inputFile string
	var outputFile string
	flag.StringVar(&inputFile, "f", "", "应用描述文件")
	flag.StringVar(&outputFile, "o", "", "输出文件")
	flag.Parse()
	inputFile = os.Args[1]
	for k,v:= range os.Args{
		if v == "-o" {
			outputFile = os.Args[k+1]
		}
	}
	if inputFile == "" {
		fmt.Println("请输入描述文件")
		os.Exit(0)
	}
	text,err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	if len(text) == 0{
		fmt.Println("描述文件内容不能为空")
		os.Exit(0)
	}


}