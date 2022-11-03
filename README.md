# TokenAware
TokenAware is a framework to detect the token behavior on ethereum.

# Paper
You can find our paper about the design, implementation, and experimental results of TokenAware at https://dl.acm.org/doi/pdf/10.1145/3560263.

> This work proposes TokenAware, a novel online system for recognizing token transfer behaviors. To improve accuracy, TokenAware infers token transfer behaviors from modifications of internal bookkeeping of a token smart contract for recording the information of token holders (e.g., their addresses and shares). However, recognizing bookkeeping is challenging because smart contract bytecode does not contain type information. TokenAware overcomes the challenge by first learning the instruction sequences for locating basic types and then deriving the instruction sequences for locating sophisticated types that are composed of basic types. To improve efficiency, TokenAware introduces four optimizations. We conduct extensive experiments to evaluate TokenAware with real blockchain data. Results show that TokenAware can automatically identify new types of bookkeeping and recognize 107,202 tokens with 98.7% precision. TokenAware with optimizations merely incurs 4% overhead, which is 1/345 of the overhead led by the counterpart with no optimization. Moreover, we develop an application based on TokenAware to demonstrate how it facilitates malicious behavior detection.

# Citing in Academic Work

Welcome to cite our paper:
```shell
@article{tokenaware,
author = {He, Zheyuan and Song, Shuwei and Bai, Yang and Luo, Xiapu and Chen, Ting and Zhang, Wensheng and He, Peng and Li, Hongwei and Lin, Xiaodong and Zhang, Xiaosong},
title = {TokenAware: Accurate and Efficient Bookkeeping Recognition for Token Smart Contracts},
year = {2022},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
issn = {1049-331X},
url = {https://doi.org/10.1145/3560263},
doi = {10.1145/3560263},
note = {Just Accepted},
journal = {ACM Trans. Softw. Eng. Methodol.},
month = {aug},
keywords = {smart contract, token, bookkeeping recognition, Ethereum}
}
```

# The Catalog of TokenAware

## source code
The source code is in tokenaware-application. 
There are two part of the framework, first you need to configurate the environment about the oyente and go-ethereum.
Then you should set the oyente path (Oyente Path varieble) with your own path in /root/TokenAware/tokenaware-application-1/datalog/path.go.
Finally you an run geth with "geth --datadir tokenawaredata --syncmode full" to detect the token behavior.
The result will in the temp file in your Tokenaware dir.

## experiment result
 * `FraudulentTransfer.xlsx`：the infomation about the application.
 
 
# Contact us
If you have any problems in using our tool, please send emails to ecjgvmhc@gmail.com
