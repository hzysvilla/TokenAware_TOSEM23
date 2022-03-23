#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import logging
import os
import re
# import shlex
import subprocess
import time

import requests

import global_params
import symExec
from source_map import SourceMap
from utils import run_command

EVM_PATH = "/usr/bin/evm"
VYPER_FEATURE_STR = "600035601c52740100000000000000000000000000000000000000006020526f7fffffffffffffffffffffffffffffff6040527fffffffffffffffffffffffffffffffff8000000000000000000000000000000060605274012a05f1fffffffffffffffffffffffffdabf41c006080527ffffffffffffffffffffffffed5fa0e000000000000000000000000000000000060a052"


def write(path, mode, data):
    with open(path, mode) as f:
        f.write(data)
    f.close()


def cmd_exists(cmd):
    return subprocess.call("type " + cmd,
                           shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE) == 0


def has_dependencies_installed():
    try:
        import z3
        import z3.z3util
    except:
        logging.critical(
            "Z3 is not available. Please install z3 from https://github.com/Z3Prover/z3."
        )
        return False

    if not cmd_exists("evm"):
        logging.critical(
            "Please install evm from go-ethereum and make sure it is in the path."
        )
        return False

    return True


def removeSwarmHash(evm):
    evm_without_hash = re.sub(r"a165627a7a72305820\S{64}0029$", "", evm)
    return evm_without_hash


# [x] source_map
def analyze(processed_evm_file, disasm_file, source_map=None):
    time1 = time.time()
    disasm_out = ""
    try:
        disasm_p = subprocess.Popen([EVM_PATH, "disasm", processed_evm_file],
                                    stdout=subprocess.PIPE)
        disasm_out = disasm_p.communicate()[0]
    except:
        logging.critical("Disassembly failed.")
        exit()

    with open(disasm_file, 'w') as of:
        of.write(disasm_out)
    time2 = time.time()
    if source_map != None:
        symExec.main(disasm_file, args.source, source_map)
    else:
        symExec.main(disasm_file, args.source)
    time2 = time.time()


def remove_temporary_file(path):
    if os.path.isfile(path):
        os.unlink(path)


def main():
    # time1 = time.time()  # by hao
    global args

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-s",
        "--source",
        type=str,
        help=
        "local source file name. Solidity by default. Use -b to process evm instead. Use stdin to read from stdin."
    )
    parser.add_argument("--version",
                        action="version",
                        version="oyente version 0.2.7 - Commonwealth")
    parser.add_argument(
        "-b",
        "--bytecode",
        help="read bytecode in source instead of solidity file.",
        action="store_true")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    if not has_dependencies_installed():
        return
    if args.bytecode:
        processed_evm_file = args.source + '.1'
        disasm_file = args.source + '.disasm'
        with open(args.source) as f:
            evm = f.read()
        # 判断是否是vyper合约 --added by heppen
        if VYPER_FEATURE_STR in evm:
            return

        with open(processed_evm_file, 'w') as f:
            f.write(removeSwarmHash(evm))

        analyze(processed_evm_file, disasm_file)

        remove_temporary_file(disasm_file)
        remove_temporary_file(processed_evm_file)


if __name__ == '__main__':
    main()
