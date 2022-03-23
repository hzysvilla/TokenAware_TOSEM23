# -*- coding: utf-8 -*-
import atexit
import base64
import json
import logging
import math
import pickle
import re
import signal
import sys
import time
import tokenize
import traceback
import zlib
from collections import namedtuple
from tokenize import NAME, NEWLINE, NUMBER

import pprint
from z3 import *

import global_params
# from analysis import *
from basicblock import BasicBlock
from ethereum_data import *
from opcodes import getOpcodeParams
from test_evm.global_test_params import (EXCEPTION, PICKLE_PATH, TIME_OUT,
                                         UNKOWN_INSTRUCTION)
from tools import *
from vargenerator import *

import restore_ds

from path import Path

log = logging.getLogger(__name__)

UNSIGNED_BOUND_NUMBER = 2**256 - 1
CONSTANT_ONES_159 = BitVecVal((1 << 160) - 1, 256)

SPLIT_CHAR = "///"  # 记录opcode信息时字符串的分隔符
TRANSFER_METHOD_ID = "0xa9059cbb"
TRANSFERFROM_METHOD_ID = "0x23b872dd"
# SAFE_TRANSFERFROM_METHOD_ID = "0xf242432a"  # ERC1155标准
# ERC721_SAFE_TRANSFERFROM = "0x42842e0e"  # ERC721标准
# ERC721_SAFE_TRANSFERFROM_2 = "0xb88d4fde"  # ERC721标准


isVyper = False
Assertion = namedtuple('Assertion', ['pc', 'model'])
is_infinite = False
# is_erc1155 = False


class Parameter:
    def __init__(self, **kwargs):
        attr_defaults = {
            "instr": "",
            "block": 0,
            "depth": 0,
            "pre_block": 0,
            "stack": [],
            "visited": [],
            "mem": {},
            "global_state": {},
            "path_conditions_and_vars": {},

            # 自定义stack/memory/storage --added by heppen
            "pattern_stack": [],
            "pattern_memory": {},
            "pattern_storage": {},
            "opcode_list": [],  # 存储所有和地址操作相关的op序列
            "methodid": "",
            "methodiddata": {},
            "return_blocks": [],  # 内部函数返回的block
            "inner_edges": {},  # 内部函数经过的边，用于后面释放

            # 存储未优化表达式
            "origin_pattern_stack": [],
            "origin_pattern_mem": {},
            "origin_pattern_storage": {},

            "jumpi_flag": -1,
            "is_vyper_enter_loop": False,
            "sstore_info_in_path": [],  # 每一条路径中sstore的key值
            "event_info_in_path": [],  # 每一条路径中log的参数
            "has_call_in_path": False,  # 路径中是否存在call
            "lt_in_path": [],  # LT操作和零进行比较的参数
            "gt_in_path": [],  # GT操作和零进行比较的参数
            "eq_in_path": [],  # EQ操作的两个参数
            "iszero_in_path": [],  # 路径中iszero的参数
            "jumpi_flags_in_path": [],  # 路径中jumpi的flag记录
        }
        for (attr, default) in attr_defaults.iteritems():
            setattr(self, attr, kwargs.get(attr, default))

    def copy(self):
        _kwargs = custom_deepcopy(self.__dict__)
        return Parameter(**_kwargs)


def initGlobalVars():
    # global solver
    # Z3 solver
    # solver = Solver()
    # solver.set("timeout", global_params.TIMEOUT)

    global any_bug
    any_bug = False

    global visited_pcs
    visited_pcs = set()

    global results
    results = {
        "evm_code_coverage": "",
        "callstack": False,
        "money_concurrency": False,
        "time_dependency": False,
        "reentrancy": False,
        "assertion_failure": False
    }

    # capturing the last statement of each basic block
    global end_ins_dict
    end_ins_dict = {}

    # capturing all the instructions, keys are corresponding addresses
    global instructions
    instructions = {}

    # capturing the "jump type" of each basic block
    global jump_type
    jump_type = {}  # key 是block 编号

    global vertices
    vertices = {}  # 存储所有的block信息，key是block的数字编号, value是BasicBlock

    global edges
    edges = {}  # 存储所有的边信息

    global visited_edges
    visited_edges = {}  # 所有被访问过的 Edge, key 是 methodid

    global reentrancy_all_paths
    reentrancy_all_paths = []

    global total_no_of_paths
    total_no_of_paths = 0  # 走到叶子节点的路径个数

    global no_of_test_cases
    no_of_test_cases = 0

    # to generate names for symbolic variables
    global gen
    gen = Generator()

    global log_file
    log_file = open(c_name + '.log', "w")

    global rfile
    if global_params.REPORT_MODE:
        rfile = open(c_name + '.report', 'w')

    global exec_blocks
    exec_blocks = 0  # 整个执行过程中访问的 block 数

    global opcode_exectime
    opcode_exectime = {}  # 整个执行过程中相同首字母opcode的执行时间
    # transfer函数中sstore的地址
    global transfer_sstore_addresses
    transfer_sstore_addresses = {}  # key为表达式，value为表达式对应的op序列

    # transferfrom函数中的sstore的地址
    global transferfrom_sstore_addresses
    transferfrom_sstore_addresses = {}

    # transfer和transferfrom以外的sstore地址
    global sstore_addresses
    sstore_addresses = {}

    global sstore_pc
    sstore_pc = {} # 一个地址表达式对应sstore的pc

    # 通过and进行地址掩码的地址变量
    global addrs_in_and
    addrs_in_and = ['Is', 'Ia']

    # 标准Transfer事件中的value值
    global values_in_transfer_event
    values_in_transfer_event = []

    # balance在storage中的偏移位数
    global shift_bit
    shift_bit = 0

    # 每一个函数内sstore的信息，key -> value
    global sstore_info
    sstore_info = {}

    # 每一个函数内标准event的三个参数
    global event_params
    event_params = []

    # 上一个访问的methodid
    global last_methodid
    last_methodid = ""

    # 是否有transfer函数
    global has_transfer
    has_transfer = False

    # 是否有transferFrom函数
    global has_transferfrom
    has_transferfrom = False

    # 两个都匹配的pattern
    global two_match_pattern
    two_match_pattern = []

    # 只匹配上method的pattern
    global method_match_pattern
    method_match_pattern = []

    # 只匹配上event的pattern
    global event_match_pattern
    event_match_pattern = []

    # 没有匹配的pattern
    global no_match_pattern
    no_match_pattern = []

    # erc1155标准事件的参数
    # global erc1155_event_params
    # erc1155_event_params = []

    # 三个标准函数对应的函数出口块号
    # 每个函数切换时需要清空
    # global out_block
    # out_block = 0

    # 每一个函数中有pattern的路径
    # key是methodid，value是路径中的block
    global g_has_pattern_path
    g_has_pattern_path = {}

    # 函数内每一条路径中sstore的key值
    # 每次函数切换时需要清空
    # dict的key是路径的字符串表示，value是路径中sstore的key信息
    global g_sstore_info_in_path
    g_sstore_info_by_path = {}

    # 存在fake notification漏洞的methodid
    global g_fake_notice
    g_fake_notice = []

    # 每条路径的信息
    global g_path_info
    g_path_info = {}


def check_unit_test_file():
    if global_params.UNIT_TEST == 1:
        try:
            open('unit_test.json', 'r')
        except Exception:
            log.critical("Could not open result file for unit test")
            exit()


def isTesting():
    return global_params.UNIT_TEST != 0


def change_format():
    with open(c_name) as disasm_file:
        file_contents = disasm_file.readlines()
        i = 0
        firstLine = file_contents[0].strip('\n')
        for line in file_contents:
            line = line.replace('SELFDESTRUCT', 'SUICIDE')
            line = line.replace('Missing opcode 0xfd', 'REVERT')
            line = line.replace('Missing opcode 0xfe', 'ASSERTFAIL')
            line = line.replace('Missing opcode', 'INVALID')
            line = line.replace(':', '')
            lineParts = line.split(' ')
            try:  # removing initial zeroes
                lineParts[0] = str(int(lineParts[0]))

            except Exception:
                lineParts[0] = lineParts[0]
            lineParts[-1] = lineParts[-1].strip('\n')
            try:  # adding arrow if last is a number
                lastInt = lineParts[-1]
                if (int(lastInt, 16)
                        or int(lastInt, 16) == 0) and len(lineParts) > 2:
                    lineParts[-1] = "=>"
                    lineParts.append(lastInt)
            except Exception:
                pass
            file_contents[i] = ' '.join(lineParts)
            i = i + 1
        file_contents[0] = firstLine
        file_contents[-1] += '\n'

    with open(c_name, 'w') as disasm_file:
        disasm_file.write("\n".join(file_contents))


def build_cfg_and_analyze():
    global source_map
    change_format()
    with open(c_name, 'r') as disasm_file:
        disasm_file.readline()  # Remove first line
        tokens = tokenize.generate_tokens(disasm_file.readline)
        collect_vertices(tokens)  # 收集所有的opcode/区块的起始和结尾opcode/特殊跳转方式
        construct_bb()  # 根据区块的起始和结尾opcode，组成vertices和edges
        construct_static_edges()  # 增加falls_to类型的边和点
        full_sym_exec()  # jump targets are constructed on the fly


def mapping_push_instruction(current_line_content, current_ins_address, idx,
                             positions, length):
    global source_map

    while (idx < length):
        if not positions[idx]:
            return idx + 1
        name = positions[idx]['name']
        if name.startswith("tag"):
            idx += 1
        else:
            if name.startswith("PUSH"):
                if name == "PUSH":
                    value = positions[idx]['value']
                    instr_value = current_line_content.split(" ")[1]
                    if int(value, 16) == int(instr_value, 16):
                        source_map.instr_positions[
                            current_ins_address] = source_map.positions[idx]
                        idx += 1
                        break
                    else:
                        raise Exception("Source map error")
                else:
                    source_map.instr_positions[
                        current_ins_address] = source_map.positions[idx]
                    idx += 1
                    break
            else:
                raise Exception("Source map error")
    return idx


def mapping_non_push_instruction(current_line_content, current_ins_address,
                                 idx, positions, length):
    global source_map

    while (idx < length):
        if not positions[idx]:
            return idx + 1
        name = positions[idx]['name']
        if name.startswith("tag"):
            idx += 1
        else:
            instr_name = current_line_content.split(" ")[0]
            if (name == instr_name
                    or name == "INVALID" and instr_name == "ASSERTFAIL"
                    or name == "KECCAK256" and instr_name == "SHA3"
                    or name == "SELFDESTRUCT" and instr_name == "SUICIDE"):
                source_map.instr_positions[
                    current_ins_address] = source_map.positions[idx]
                idx += 1
                break
            else:
                raise Exception("Source map error")
    return idx


# 1. Parse the disassembled file
# 2. Then identify each basic block (i.e. one-in, one-out)
# 3. Store them in vertices


# 主要为end_ins_dict/jump_type/instructions三个全局变量赋值
def collect_vertices(tokens):
    global source_map
    if source_map:
        idx = 0
        positions = source_map.positions
        length = len(positions)
    global end_ins_dict
    global instructions
    global jump_type

    current_ins_address = 0
    last_ins_address = 0
    is_new_line = True
    current_block = 0
    current_line_content = ""
    wait_for_push = False
    is_new_block = False

    for tok_type, tok_string, (srow, scol), _, line_number in tokens:
        if wait_for_push is True:
            push_val = ""
            for ptok_type, ptok_string, _, _, _ in tokens:
                if ptok_type == NEWLINE:
                    is_new_line = True
                    current_line_content += push_val + ' '
                    instructions[current_ins_address] = current_line_content
                    idx = mapping_push_instruction(
                        current_line_content, current_ins_address, idx,
                        positions, length) if source_map else None
                    current_line_content = ""
                    wait_for_push = False
                    break
                try:
                    int(ptok_string, 16)
                    push_val += ptok_string
                except ValueError:
                    pass

            continue
        elif (is_new_line is True
              and tok_type == NUMBER):  # looking for a line number
            last_ins_address = current_ins_address
            try:
                current_ins_address = int(tok_string)
            except ValueError:
                log.critical("ERROR when parsing row %d col %d", srow, scol)
                quit()
            is_new_line = False
            if is_new_block:
                current_block = current_ins_address
                is_new_block = False
            continue
        elif tok_type == NEWLINE:
            is_new_line = True
            instructions[current_ins_address] = current_line_content
            idx = mapping_non_push_instruction(
                current_line_content, current_ins_address, idx, positions,
                length) if source_map else None
            current_line_content = ""
            continue
        elif tok_type == NAME:
            if tok_string == "JUMPDEST":
                if last_ins_address not in end_ins_dict:
                    end_ins_dict[current_block] = last_ins_address
                current_block = current_ins_address
                is_new_block = False
            elif (tok_string == "STOP" or tok_string == "RETURN"
                  or tok_string == "SUICIDE" or tok_string == "REVERT"
                  or tok_string == "ASSERTFAIL"):
                jump_type[current_block] = "terminal"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True  # added by heppen
            elif tok_string == "JUMP":
                jump_type[current_block] = "unconditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string == "JUMPI":
                jump_type[current_block] = "conditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string.startswith('PUSH', 0):
                wait_for_push = True
            is_new_line = False
        if tok_string != "=" and tok_string != ">":
            current_line_content += tok_string + " "

    if current_block not in end_ins_dict:
        end_ins_dict[current_block] = current_ins_address

    if current_block not in jump_type:
        jump_type[current_block] = "terminal"

    for key in end_ins_dict:
        if key not in jump_type:
            jump_type[key] = "falls_to"


# 收集区块和边
def construct_bb():
    global vertices
    global edges
    sorted_addresses = sorted(instructions.keys())
    size = len(sorted_addresses)  # 所有opcode长度
    for key in end_ins_dict:
        end_address = end_ins_dict[key]
        block = BasicBlock(key, end_address)
        if key not in instructions:
            continue
        block.add_instruction(instructions[key])
        i = sorted_addresses.index(key) + 1
        while i < size and sorted_addresses[i] <= end_address:
            block.add_instruction(instructions[sorted_addresses[i]])
            i += 1
        block.set_block_type(jump_type[key])
        vertices[key] = block
        edges[key] = []


def construct_static_edges():
    add_falls_to()  # these edges are static


# 增加直接跳转(按编号大小顺序执行)的边和点
def add_falls_to():
    global vertices
    global edges
    key_list = sorted(jump_type.keys())
    length = len(key_list)
    for i, key in enumerate(key_list):
        if jump_type[key] != "terminal" and jump_type[
                key] != "unconditional" and i + 1 < length:
            target = key_list[i + 1]
            edges[key].append(target)
            vertices[key].set_falls_to(target)


def get_init_global_state(path_conditions_and_vars):
    global_state = {"balance": {}, "pc": 0}
    init_is = init_ia = deposited_value = sender_address = receiver_address = gas_price = origin = currentCoinbase = currentNumber = currentDifficulty = currentGasLimit = callData = None

    # if global_params.INPUT_STATE:
    #     with open('state.json') as f:
    #         state = json.loads(f.read())
    #         if state["Is"]["balance"]:
    #             init_is = int(state["Is"]["balance"], 16)
    #         if state["Ia"]["balance"]:
    #             init_ia = int(state["Ia"]["balance"], 16)
    #         if state["ex, 'addressinfo': {}ec"]["value"]:
    #             deposited_value = 0
    #         if state["Is"]["address"]:
    #             sender_address = int(state["Is"]["address"], 16)
    #         if state["Ia"]["address"]:
    #             receiver_address = int(state["Ia"]["address"], 16)
    #         if state["exec"]["gasPrice"]:
    #             gas_price = int(state["exec"]["gasPrice"], 16)
    #         if state["exec"]["origin"]:
    #             origin = int(state["exec"]["origin"], 16)
    #         if state["env"]["currentCoinbase"]:
    #             currentCoinbase = int(state["env"]["currentCoinbase"], 16)
    #         if state["env"]["currentNumber"]:
    #             currentNumber = int(state["env"]["currentNumber"], 16)
    #         if state["env"]["currentDifficulty"]:
    #             currentDifficulty = int(state["env"]["currentDifficulty"], 16)
    #         if state["env"]["currentGasLimit"]:
    #             currentGasLimit = int(state["env"]["currentGasLimit"], 16)

    # for some weird reason these 3 vars are stored in path_conditions insteaad of global_state
    # else:
    sender_address = BitVec("Is", 256)
    receiver_address = BitVec("Ia", 256)
    deposited_value = BitVec("Iv", 256)
    init_is = BitVec("init_Is", 256)
    init_ia = BitVec("init_Ia", 256)

    path_conditions_and_vars["Is"] = sender_address
    path_conditions_and_vars["Ia"] = receiver_address
    path_conditions_and_vars["Iv"] = deposited_value

    constraint = (deposited_value >= BitVecVal(0, 256))
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = (init_is >= deposited_value)
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = (init_ia >= BitVecVal(0, 256))
    path_conditions_and_vars["path_condition"].append(constraint)

    # update the balances of the "caller" and "callee"

    global_state["balance"]["Is"] = (init_is - deposited_value)
    global_state["balance"]["Ia"] = (init_ia + deposited_value)

    if not gas_price:
        new_var_name = gen.gen_gas_price_var()
        gas_price = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = gas_price

    if not origin:
        new_var_name = gen.gen_origin_var()
        origin = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = origin

    if not currentCoinbase:
        new_var_name = "IH_c"
        currentCoinbase = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentCoinbase

    if not currentNumber:
        new_var_name = "IH_i"
        currentNumber = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentNumber

    if not currentDifficulty:
        new_var_name = "IH_d"
        currentDifficulty = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentDifficulty

    if not currentGasLimit:
        new_var_name = "IH_l"
        currentGasLimit = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentGasLimit

    new_var_name = "IH_s"
    currentTimestamp = BitVec(new_var_name, 256)
    path_conditions_and_vars[new_var_name] = currentTimestamp

    # the state of the current current contract
    if "Ia" not in global_state:
        global_state["Ia"] = {}
    global_state["miu_i"] = 0
    global_state["value"] = deposited_value
    global_state["sender_address"] = sender_address
    global_state["receiver_address"] = receiver_address
    global_state["gas_price"] = gas_price
    global_state["origin"] = origin
    global_state["currentCoinbase"] = currentCoinbase
    global_state["currentTimestamp"] = currentTimestamp
    global_state["currentNumber"] = currentNumber
    global_state["currentDifficulty"] = currentDifficulty
    global_state["currentGasLimit"] = currentGasLimit

    return global_state


def full_sym_exec():
    global two_match_pattern
    global method_match_pattern
    global event_match_pattern
    global no_match_pattern
    global addrs_in_and
    global event_params
    global last_methodid
    global has_transfer
    global has_transferfrom
    # global is_erc1155
    # global g_sstore_info_by_path
    # executing, starting from beginning
    path_conditions_and_vars = {"path_condition": []}
    global_state = get_init_global_state(path_conditions_and_vars)
    methodid = ''
    methodiddata = {'methodid': '', 'step': 0, 'lock': False}
    params = Parameter(path_conditions_and_vars=path_conditions_and_vars,
                       global_state=global_state,
                       methodid=methodid,
                       methodiddata=methodiddata)
    sym_exec_block(params)

    # 匹配最后一个函数的event、method和map
    if (sstore_info and not isVyper):
        method_patterns = []
        event_patterns = []
        # patterns = []
        if (not two_match_pattern and last_methodid == TRANSFER_METHOD_ID):
            # __import__('pprint').pprint(sstore_info)
            has_transfer = True
            method_patterns = compare_method_map_transfer(sstore_info, addrs_in_and)
        if (not two_match_pattern and last_methodid == TRANSFERFROM_METHOD_ID):
            has_transferfrom = True
            method_patterns = compare_method_map_transferfrom(sstore_info, addrs_in_and)
        # if (not two_match_pattern and last_methodid == SAFE_TRANSFERFROM_METHOD_ID):
        #     print "erc1155"  # debug
        #     is_erc1155 = True
        #     method_patterns = erc1155_compare_method_map(sstore_info, addrs_in_and)

        # 判断是否有fake depoist漏洞
        # if (last_methodid in (TRANSFER_METHOD_ID, TRANSFERFROM_METHOD_ID, SAFE_TRANSFERFROM_METHOD_ID) and method_patterns):
        #     if (not check_fake_deposit(g_sstore_info_by_path, method_patterns, addrs_in_and)):
        #         print "FAKE DEPOSIT!!", last_methodid

        if (event_params and not two_match_pattern):
            event_patterns = compare_event_map(event_params, sstore_info, addrs_in_and)
        # if (erc1155_event_params and not two_match_pattern):
        #     event_patterns = erc1155_compare_event_map(erc1155_event_params, sstore_info, addrs_in_and)
            # print event_patterns
        if method_patterns and event_patterns:
            for p in method_patterns:
                if p not in event_patterns:
                    # print "method pattern is diff with event pattern!"
                    continue;
                else:
                    two_match_pattern.append(p)
        for p in method_patterns:
            if p not in method_match_pattern:
                method_match_pattern.append(p)
        for p in event_patterns:
            if p not in event_match_pattern:
                event_match_pattern.append(p)
        if (not method_patterns and not event_patterns):
            no_match_pattern += no_match_compare(sstore_info, addrs_in_and)
    # if (sstore_info and isVyper):
    #     # method_match_map = False
    #     method_patterns = []
    #     event_patterns = []
    #     # patterns = []
    #     if (not two_match_pattern and last_methodid == TRANSFER_METHOD_ID):
    #         # __import__('pprint').pprint(sstore_info)
    #         has_transfer = True
    #         # print sstore_info  # debug
    #         method_patterns = vyper_compare_method_map_transfer(sstore_info, addrs_in_and)
    #     if (not two_match_pattern and last_methodid == TRANSFERFROM_METHOD_ID):
    #         # print sstore_info
    #         has_transferfrom = True
    #         method_patterns = vyper_compare_method_map_transferfrom(sstore_info, addrs_in_and)
    #     # if (not two_match_pattern and last_methodid == SAFE_TRANSFERFROM_METHOD_ID):
    #     #     print "erc1155"  # debug
    #     #     is_erc1155 = True
    #     #     # print "erc1155"  # debug
    #     #     method_patterns = erc1155_compare_method_map(sstore_info, addrs_in_and)

    #     # 判断是否有fake depoist漏洞
    #     # if (last_methodid in (TRANSFER_METHOD_ID, TRANSFERFROM_METHOD_ID, SAFE_TRANSFERFROM_METHOD_ID) and method_patterns):
    #     #     if (not check_fake_deposit(g_sstore_info_by_path, method_patterns, addrs_in_and)):
    #     #         print "FAKE DEPOSIT!!", last_methodid

    #     if (not two_match_pattern):
    #         event_patterns = compare_event_map(event_params, sstore_info, addrs_in_and)
    #     if (erc1155_event_params and not two_match_pattern):
    #         event_patterns = erc1155_compare_event_map(erc1155_event_params, sstore_info, addrs_in_and)
    #     if method_patterns and event_patterns:
    #         for p in method_patterns:
    #             if p not in event_patterns:
    #                 # print "method pattern is diff with event pattern!"
    #                 continue;
    #             else:
    #                 two_match_pattern.append(p)
    #     for p in method_patterns:
    #         if p not in method_match_pattern:
    #             method_match_pattern.append(p)
    #     for p in event_patterns:
    #         if p not in event_match_pattern:
    #             event_match_pattern.append(p)
    #     if (not method_patterns and not event_patterns):
    #         no_match_pattern += no_match_compare(sstore_info, addrs_in_and)


def sym_exec_block(params):
    # global solver
    global visited_edges
    global results  # 存储最后的分析结果
    global source_map
    global exec_blocks
    global opcode_exectime

    global method_abi  # store everything

    global isVyper
    global is_infinite
    # global is_erc1155
    global g_path_info
    global addrs_in_and
    block = params.block
    pre_block = params.pre_block
    visited = params.visited  # 访问过的 block 序列
    depth = params.depth  # block 在访问路径中的深度
    stack = params.stack
    mem = params.mem  # 以地址作为 key 的同步 memory dict，一般 key 为实数
    global_state = params.global_state
    path_conditions_and_vars = params.path_conditions_and_vars

    # 自定义和pattern相关的stack/memory/storage. added by heppen
    pattern_stack = params.pattern_stack
    pattern_memory = params.pattern_memory
    pattern_storage = params.pattern_storage
    opcode_list = params.opcode_list

    # 存储未优化表达式
    origin_pattern_stack = params.origin_pattern_stack
    origin_pattern_mem = params.origin_pattern_mem
    origin_pattern_storage = params.origin_pattern_storage

    # vyper_loop_block = params.vyper_loop_block
    # vyper_loop_edge = params.vyper_loop_edge

    methodid = params.methodid
    methodiddata = params.methodiddata

    return_blocks = params.return_blocks
    inner_edges = params.inner_edges
    # added by heppen

    # print "isVyper:", isVyper
    # Edge 数据类型定义
    Edge = namedtuple("Edge", ["v1", "v2"])
    if block < 0:
        return ["ERROR"]

    # 上一个 block 到当前 block 组成一条边
    current_edge = Edge(pre_block, block)
    # 当前 methodid 下访问过的边
    the_visited_edges = visited_edges.get(methodid, {})
    # 更新边的访问次数
    # 之前访问过的边次数加1， 未被访问过的设置为1
    if current_edge in the_visited_edges:
        updated_count_number = the_visited_edges[current_edge] + 1
        the_visited_edges.update({current_edge: updated_count_number})
    else:
        the_visited_edges.update({current_edge: 1})

    # if isVyper and params.is_vyper_enter_loop:
    #     updated_count_number = the_visited_edges[current_edge] - 1
    #     the_visited_edges.update({current_edge: updated_count_number})

    visited_edges[methodid] = the_visited_edges  # 更新全局边访问次数变量

    # 判断边的访问次数是否超过预先设定的次数限制
    if the_visited_edges[current_edge] > global_params.LOOP_LIMIT:
        # 路径结束前，判断是否有fake notificaiton漏洞
        # 路径结束，存储路径的相关信息
        path_info = Path(methodid, params, addrs_in_and, False)
        g_path_info[tuple(params.visited)] = path_info
        return stack

    # if methodid == TRANSFER_METHOD_ID:
    #     print methodid, block, jump_type[block], return_blocks, pre_block
    #     print visited
    #     __import__('pprint').pprint(inner_edges)

    try:
        block_ins = vertices[block].get_instructions()
    except KeyError:
        return ["ERROR"]

    exec_blocks += 1
    if exec_blocks > 20000:
        # log.info("over blocks!")
        is_infinite = True
        return ["ERROR"]

    # 记录内部函数经过的路径 -- added by heppen
    if not is_infinite and methodid and return_blocks:
        last_block = return_blocks[-1]
        # 不是内部函数的第一个block
        if last_block in inner_edges:
            is_circle = False
            # 判断是否形成环，如果形成环，不记录形成环的边
            for edge in inner_edges[last_block]:
                if edge.v1 == block:
                    is_circle = True
                    # 如果形成环，则将形成环的那条边从已经记录边中删除
                    if current_edge in inner_edges[last_block]:
                        index = inner_edges[last_block].index(current_edge)
                        inner_edges[last_block].pop(index)
                    break
            if not is_circle:
                inner_edges[last_block].append(current_edge)
        # 内部函数的第一个block
        else:
            # length为1说明刚进入payable检查
            # length为2说明进入第一层内部函数
            # 不记录这种情况的进入边
            # if not isVyper:
            if len(return_blocks) <= 2:
                inner_edges[last_block] = []
            else:
                inner_edges[last_block] = [current_edge]
            # else:
            #     if return_blocks:
            #         inner_edges[last_block] = [current_edge]
            #     # if vyper_loop_block:
            #     #     vyper_loop_edge[vyper_loop_block[-1]] = [current_edge]

    Previous_op = ''

    for instr in block_ins:

        thispc = global_state["pc"]

        # print thispc, instr, "=>", params.origin_pattern_stack
        time1 = time.time()  # by hao
        params.instr = instr

        sym_exec_ins(params, Previous_op)

        # if not is_infinite and isVyper and jump_type[block] == "unconditional" and instr == "ADD " and Previous_op == "PC ":
        #     value = params.stack[0]
        #     if (value >= thispc+ 1 and value in vertices and 
        #             vertices[value].get_first_opcode() == 'JUMPDEST '
        #             and value not in return_blocks):
        #         return_blocks.append(value)

        # 获取每条opcode的执行时间 [x]
        time2 = time.time()  # by hao
        instrinfo = instr.split(' ')
        thestr = instr[0]  # instr => 'PUSH1 0x80' 取opcode首字母作用?
        temp = opcode_exectime.get(thestr, [])  # by hao
        temp.append(time2 - time1)  # by hao
        opcode_exectime[thestr] = temp  # by hao
        Previous_op = instr
        # 判断pattern_stack是否和stack高度一样
        if len(pattern_stack) != len(stack):
            log.info("stack length inconsit")
            log.info("stack: %d pattern_stack: %d", len(stack),
                     len(pattern_stack))
            exit()
        # 判断origin_pattern_stack是否和stack高度一样
        if len(origin_pattern_stack) != len(stack):
            log.info("stack length inconsit")
            log.info("stack: %d origin_pattern_stack: %d", len(origin_pattern_stack), len(pattern_stack))
            exit()

    visited.append(block)
    depth += 1

#     if methodid == TRANSFER_METHOD_ID:
#         print methodid, block, jump_type[block], return_blocks, pre_block
#         print visited

    # Go to next Basic Block(s)
    if jump_type[block] == "terminal" or depth > global_params.DEPTH_LIMIT:
        global total_no_of_paths
        global no_of_test_cases

        # 路径结束前，判断是否有fake notificaiton漏洞
        # if methodid == "0x8863c8d5":
        #     print "EQ:", params.eq_in_path, params.event_info_in_path, params.gt_in_path
        # 路径正常结束，存储路径中的信息
        if block_ins[-1] == "STOP " or block_ins[-1] == "RETURN ":
            path_info = Path(methodid, params, addrs_in_and, True)
            g_path_info[tuple(params.visited)] = path_info
        # if methodid not in g_fake_notice and check_fake_notice(params):
        #     g_fake_notice.append(methodid)
        total_no_of_paths += 1

    elif jump_type[block] == "unconditional":  # executing "JUMP"
        successor = vertices[block].get_jump_target()

        # 判断下一个块是否是内部函数块 -- added by heppen
        if (not isVyper and not is_infinite and methodid and "CALLDATALOAD " not in block_ins and "CALLVALUE " not in block_ins):
        # if (not is_infinite and methodid and "CALLVALUE " not in block_ins):
            for opcode_str in block_ins[:-2]:
                if not opcode_str.startswith("PUSH"):
                    continue
                push_addr = -1
                if opcode_str.split()[1]:
                    push_addr = int(opcode_str.split()[1], 16)
                # 要求push的值比当前pc大
                # 并且push的值是一个block的开始值(最好是jumpdest开始的block)
                # push的值不在记录的返回地址中
                if (push_addr < global_state["pc"] + 1
                        or push_addr not in vertices or
                        vertices[push_addr].get_first_opcode() != 'JUMPDEST '
                        or push_addr in return_blocks):
                    continue
                return_blocks.append(push_addr)

        # 判断下一个块是否是内部函数返回上一层函数 --added by heppen
        if (not is_infinite and methodid and return_blocks and successor == return_blocks[-1]
                and not block_ins[-2].startswith("PUSH")):
            # 释放内部函数经过的路径
            ret_block = return_blocks.pop()
            the_visited_edges = visited_edges.get(methodid, {})
            if ret_block in inner_edges:  # 返回的目的block有对应的内部边
                for edge in inner_edges[ret_block]:
                    if edge not in the_visited_edges:
                        continue
                    updated_count_number = 0
                    # 防止无限释放边
                    if the_visited_edges[edge] > 0:
                        updated_count_number = the_visited_edges[edge] - 1
                    the_visited_edges.update({edge: updated_count_number})
                visited_edges[methodid] = the_visited_edges
                del inner_edges[ret_block]
        # if (isVyper and vyper_loop_block and successor ==  vyper_loop_block[-1]):
        #     the_visited_edges = visited_edges.get(methodid, {})
        #     for edge in vyper_loop_edge:
        #         if edge not in the_visited_edges:
        #             continue
        #         updated_count_number = 0
        #         if the_visited_edges[edge] > 0:
        #             updated_count_number = the_visited_edges[edge] - 1
        #         the_visited_edges.update({edge: updated_count_number})
        #     visited_edges[methodid] = the_visited_edges


        # 分支开始，拷贝一份当前状态给执行分支使用，保证分支点的数据不变
        new_params = params.copy()
        new_params.depth = depth
        new_params.block = successor
        new_params.pre_block = block
        new_params.global_state["pc"] = successor

        # jump和jumpi跳转目的块的首个opcode需要是JUMPDEST
        target_first_opcode = ''
        if successor in vertices and vertices[successor].instructions:
            target_first_opcode = vertices[successor].get_first_opcode()
        if "JUMPDEST" in target_first_opcode:
            sym_exec_block(new_params)
    elif jump_type[block] == "falls_to":  # just follow to the next basic block
        # 进行变量的拷贝，保证执行完一个分支后，分支点的数据不改变
        successor = vertices[block].get_falls_to()
        new_params = params.copy()
        new_params.depth = depth
        new_params.block = successor
        new_params.pre_block = block
        new_params.global_state["pc"] = successor

        sym_exec_block(new_params)
    elif jump_type[block] == "conditional":  # executing "JUMPI"
        global last_methodid
        global sstore_info
        global event_params
        global has_transfer
        global has_transferfrom
        global two_match_pattern
        global method_match_pattern
        global event_match_pattern
        global no_match_pattern
        # global g_sstore_info_by_path

        # if isVyper and params.jumpi_flag == 0:
        #     branch = vertices[block].get_falls_to()
        #     params.block = branch
        #     params.pre_block = block
        #     params.global_state["pc"] = branch
        #     # return_blocks.append(block)
        #     params.is_vyper_enter_loop = True
        #     sym_exec_block(params)
        # elif isVyper and params.jumpi_flag == 1:
        #     branch = vertices[block].get_jump_target()
        #     params.block = branch
        #     params.pre_block = block
        #     params.global_state["pc"] = branch
        #     params.is_vyper_enter_loop = False
        #     target_first_opcode = ''
        #     if branch in vertices and vertices[branch].instructions:
        #         target_first_opcode = vertices[branch].get_first_opcode()
        #     if "JUMPDEST" in target_first_opcode:
        #         sym_exec_block(params)

        # else:
            # 走jumpi的目标跳转分支
        try:
            left_branch = vertices[block].get_jump_target()
            new_params = params.copy()
            new_params.depth = depth
            new_params.block = left_branch
            new_params.pre_block = block
            new_params.global_state["pc"] = left_branch

            # last_idx = len(  # [?]
            #     new_params.path_conditions_and_vars["path_condition"]) - 1

            target_first_opcode = ''
            if left_branch in vertices and vertices[left_branch].instructions:
                target_first_opcode = vertices[left_branch].get_first_opcode()
            if "JUMPDEST" in target_first_opcode:
                # methodid的变换
                # solidity合约匹配上methodid时，函数体是在jumpi_target分支
                methodid_now = new_params.methodiddata.get('methodid')
                step_now = new_params.methodiddata.get('step')
                # if not isVyper and methodid_now != '' and step_now == 4:
                if methodid_now != '' and step_now == 4:
                    # 函数跳转时刻
                    # 关联事件和函数
                    if new_params.methodid != methodid_now:
                        # 匹配函数与map
                        method_patterns = []
                        event_patterns = []
                        if (not two_match_pattern and last_methodid == TRANSFER_METHOD_ID):
                            # __import__('pprint').pprint(sstore_info)
                            has_transfer = True
                            method_patterns = compare_method_map_transfer(sstore_info, addrs_in_and)
                            # print method_patterns
                            # print "method change:", event_params
                        if (not two_match_pattern and last_methodid == TRANSFERFROM_METHOD_ID):
                            has_transferfrom = True
                            method_patterns = compare_method_map_transferfrom(sstore_info, addrs_in_and)
                        # if (not two_match_pattern and last_methodid == SAFE_TRANSFERFROM_METHOD_ID):
                        #     # print "erc1155"
                        #     is_erc1155 = True
                        #     # __import__('pprint').pprint(sstore_info)
                        #     method_patterns = erc1155_compare_method_map(sstore_info, addrs_in_and)
                        #     # print method_patterns

                        # 判断是否有fake depoist漏洞
                        # if (last_methodid in (TRANSFER_METHOD_ID, TRANSFERFROM_METHOD_ID, SAFE_TRANSFERFROM_METHOD_ID) and method_patterns):
                        #     if (not check_fake_deposit(g_sstore_info_by_path, method_patterns, addrs_in_and)):
                        #         print "FAKE DEPOSIT!!", last_methodid

                        if (event_params and not two_match_pattern):
                            event_patterns = compare_event_map(event_params, sstore_info, addrs_in_and)
                        # if (erc1155_event_params and not two_match_pattern):
                        #     event_patterns = erc1155_compare_event_map(erc1155_event_params, sstore_info, addrs_in_and)
                        if method_patterns and event_patterns:
                            for p in method_patterns:
                                if p not in event_patterns:
                                    continue;
                                else:
                                    two_match_pattern.append(p)
                        for p in method_patterns:
                            if p not in method_match_pattern:
                                method_match_pattern.append(p)
                        for p in event_patterns:
                            if p not in event_match_pattern:
                                event_match_pattern.append(p)
                        if (not method_patterns and not event_patterns):
                            no_match_pattern += no_match_compare(sstore_info, addrs_in_and)

                        event_params = []
                        sstore_info = {}
                        addrs_in_and = ["Is", "Ia"]
                        last_methodid = methodid_now
                        # g_sstore_info_by_path = {}

                    new_params.methodid = methodid_now
                    new_params.methodiddata['lock'] = True
                sym_exec_block(new_params)
        except Exception as e:
            log_file.write(str(e))
            log.info("jumpi exception: %s, %d", e.message, block)
            if not global_params.IGNORE_EXCEPTIONS:
                if str(e) == "timeout":
                    write('coverage-report', 'a', 'Timeout!!!\n')
                    raise e
        # 走jumpi的紧接着的block
        try:
            right_branch = vertices[block].get_falls_to()
            new_params = params.copy()
            new_params.depth = depth
            new_params.block = right_branch
            new_params.pre_block = block
            new_params.global_state["pc"] = right_branch
            # last_idx = len(
            #     new_params.path_conditions_and_vars["path_condition"]) - 1
            # vyper合约匹配上methodid时，falls_to分支是函数体
            methodid_now = new_params.methodiddata.get('methodid')
            step_now = new_params.methodiddata.get('step')
            # if isVyper and methodid_now != '' and step_now == 7:
            #     # 函数跳转时刻
            #     if new_params.methodid != methodid_now:
            #         # 匹配函数与map
            #         method_patterns = []
            #         event_patterns = []
            #         # print sstore_info
            #         if (not two_match_pattern and last_methodid == TRANSFER_METHOD_ID):
            #             # print sstore_info, addrs_in_and
            #             has_transfer = True
            #             method_patterns = vyper_compare_method_map_transfer(sstore_info, addrs_in_and)
            #         if (not two_match_pattern and last_methodid == TRANSFERFROM_METHOD_ID):
            #             has_transferfrom = True
            #             # print sstore_info
            #             method_patterns = vyper_compare_method_map_transferfrom(sstore_info, addrs_in_and)
            #         # if (not two_match_pattern and last_methodid == SAFE_TRANSFERFROM_METHOD_ID):
            #         #     is_erc1155 = True
            #         #     method_patterns = erc1155_compare_method_map(sstore_info, addrs_in_and)

            #         # 判断是否有fake depoist漏洞
            #         # if (last_methodid in (TRANSFER_METHOD_ID, TRANSFERFROM_METHOD_ID, SAFE_TRANSFERFROM_METHOD_ID) and method_patterns):
            #         #     if (not check_fake_deposit(g_sstore_info_by_path, method_patterns, addrs_in_and)):
            #         #         print "FAKE DEPOSIT!!", last_methodid

            #         if (event_params and not two_match_pattern):
            #             event_patterns = compare_event_map(event_params, sstore_info, addrs_in_and)
            #         if (erc1155_event_params and not two_match_pattern):
            #             event_patterns = erc1155_compare_event_map(erc1155_event_params, sstore_info, addrs_in_and)
            #         if method_patterns and event_patterns:
            #             for p in method_patterns:
            #                 if p not in event_patterns:
            #                     continue;
            #                 else:
            #                     two_match_pattern.append(p)
            #         for p in method_patterns:
            #             if p not in method_match_pattern:
            #                 method_match_pattern.append(p)
            #         for p in event_patterns:
            #             if p not in event_match_pattern:
            #                 event_match_pattern.append(p)
            #         if (not method_patterns and not event_patterns):
            #             no_match_pattern += no_match_compare(sstore_info, addrs_in_and)
            #         event_params = []
            #         sstore_info = {}
            #         addrs_in_and = ["Is", "Ia"]
            #         last_methodid = methodid_now
            #         # g_sstore_info_by_path = {}

            #     new_params.methodid = methodid_now
            #     new_params.methodiddata['lock'] = True
            sym_exec_block(new_params)
        except Exception as e:
            log_file.write(str(e))
            log.info("jumpi falls to exception: %s, %d", e.message, block)
            if not global_params.IGNORE_EXCEPTIONS:
                if str(e) == "timeout":
                    write('coverage-report', 'a', 'Timeout!!!\n')
                    raise e

    else:
        the_visited_edges = visited_edges.get(methodid, {})

        if current_edge in the_visited_edges:
            updated_count_number = the_visited_edges[current_edge] - 1
            the_visited_edges.update({current_edge: updated_count_number})
            visited_edges[methodid] = the_visited_edges


def z3_abs(x):
    return If(x >= 0, x, -x)


# Symbolically executing an instruction
def sym_exec_ins(params, Previous_op):
    global visited_pcs  # 访问过的pc序列
    # global solver
    global vertices
    global edges
    global source_map
    global addrs_in_and
    global sstore_info
    global g_fake_notice
    start = params.block
    instr = params.instr
    stack = params.stack
    mem = params.mem
    global_state = params.global_state
    path_conditions_and_vars = params.path_conditions_and_vars

    visited_pcs.add(global_state["pc"])

    # 自定义的相关栈和memory -- added by heppen
    pattern_stack = params.pattern_stack  # 存储对应栈中的元素是否和操作address相关
    pattern_memory = params.pattern_memory  # 存储对应memory中的元素是否和操作的address相关
    pattern_storage = params.pattern_storage
    opcode_list = params.opcode_list  # 存储和地址操作相关的opcode序列
    # 存储未优化表达式
    origin_pattern_stack = params.origin_pattern_stack
    origin_pattern_mem = params.origin_pattern_mem
    origin_pattern_storage = params.origin_pattern_storage

    methodid = params.methodid
    methodiddata = params.methodiddata
    # added by heppen

    instr_parts = instr.split(' ')

    # 变更methodid
    # if isVyper:
    #     vyper_methodid_process(instr_parts, methodiddata)
    # else:
    solidity_methodid_process(instr_parts, methodiddata)

    if instr_parts[0] == "INVALID":
        return
    elif instr_parts[0] == "ASSERTFAIL":
        return

    #
    #  0s: Stop and Arithmetic Operations
    #
    if instr_parts[0] == "STOP":
        global_state["pc"] = global_state["pc"] + 1
        # if methodid == TRANSFER_METHOD_ID or methodid == TRANSFERFROM_METHOD_ID or methodid == SAFE_TRANSFERFROM_METHOD_ID:
        #     if not sstore_info:
        #         print "FAKE DEPOSIT!", methodid
        #     else:
        #         global out_block
        #         out_block = params.pre_block
        return
    elif instr_parts[0] == "ADD":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)
        if isAllReal(first, second):
            computed = first + second
        else:
            if first == 0:
                computed = second
            elif second == 0:
                computed = first
            else:
                computed = "(%s + %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "add(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    elif instr_parts[0] == "MUL":
        global values_in_transfer_event
        global shift_bit
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if isAllReal(first, second):
            computed = first * second
        else:
            if first == 0 or second == 0:
                computed = 0
            elif first == 1:
                computed = second
            elif second == 1:
                computed = first
            elif isReal(first) and first & 2 == 0:
                computed = "(%s << %d)" % (str(second), math.log(first, 2))
                if methodid == TRANSFER_METHOD_ID and ('Cload(36)' in second):
                    shift_bit = int(math.log(first, 2))
                    # print "left: %d" % math.log(first, 2)
                elif methodid == TRANSFERFROM_METHOD_ID and (
                        'Cload(68)' in second):
                    # print "left: %d" % math.log(first, 2)
                    shift_bit = int(math.log(first, 2))
                # print values_in_transfer_event
                first = hex(first)
            elif isReal(second) and second & 2 == 0:
                computed = "(%s << %d)" % (str(first), math.log(second, 2))
                if methodid == TRANSFER_METHOD_ID and ('Cload(36)' in first):
                    # print "left: %d" % math.log(second, 2)
                    shift_bit = int(math.log(second, 2))
                elif methodid == TRANSFERFROM_METHOD_ID and (
                        'Cload(68)' in first):
                    # print "left: %d" % math.log(second, 2)
                    shift_bit = int(math.log(second, 2))
                # print values_in_transfer_event
                second = hex(second)
            else:
                computed = "(%s * %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "mul(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    elif instr_parts[0] == "SUB":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if isAllReal(first, second):
            computed = first - second
        else:
            if first == 0:
                computed = second
            elif second == 0:
                computed = first
            else:
                computed = "(%s - %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "sub(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    elif instr_parts[0] == "DIV":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if second == 0:
            computed = 0
        elif str(first) == str(second):
            computed = 1
        elif second == 1:
            computed = first
        elif isAllReal(first, second):
            first = to_unsigned(first)
            second = to_unsigned(second)
            computed = first / second
        elif isReal(second) and second & 2 == 0:
            computed = "%s >> %d" % (str(first), math.log(second, 2))
            second = hex(second)
        else:
            computed = "(% s / %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "div(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    elif instr_parts[0] == "SDIV":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if second == 0:
            computed = 0
        elif second == 1:
            computed = first
        elif str(first) == str(second):
            computed = 1
        elif isAllReal(first, second):
            first = to_signed(first)
            second = to_signed(second)
            if first == -2**255 and second == -1:
                computed = -2**255
            else:
                sign = -1 if (first / second) < 0 else 1
                computed = sign * (abs(first) / abs(second))
        else:
            computed = "(%s / %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "sdiv(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)
        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    elif instr_parts[0] == "MOD":  # 无符号数Mod
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if second == 0 or second == 1 or str(first) == str(second):
            computed = 0
        elif isAllReal(first, second):
            first = to_unsigned(first)
            second = to_unsigned(second)
            computed = first % second & UNSIGNED_BOUND_NUMBER
        else:
            computed = "(%s MOD %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "mod(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    elif instr_parts[0] == "SMOD":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if second == 0 or second == 1 or str(first) == str(second):
            computed = 0
        elif isAllReal(first, second):
            first = to_signed(first)
            second = to_signed(second)
            sign = -1 if first < 0 else 1
            computed = sign * (abs(first) % abs(second))
        else:
            computed = "(%s SMOD %s)" % (str(first), str(second))

        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "smod(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    elif instr_parts[0] == "ADDMOD":
        if len(stack) < 3:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)
        third = stack.pop(0)

        if third == 0 or third == 1:
            computed = 0
        elif isAllReal(first, second, third):
            computed = (first + second) % third
        else:
            if isAllReal(first, second):
                computed = "(%d ADDMOD %s)" % (first + second, third)
            else:
                computed = "((%s + %s) ADDMOD %s)" % (str(first), str(second),
                                                      str(third))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_third = origin_pattern_stack.pop(0)
        origin_computed = "addmod(%s, %s, %s)" % (str(origin_first), str(origin_second), str(origin_third))
        origin_pattern_stack.insert(0, origin_computed)
        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        pattern_third = pattern_stack.pop(0)
        if pattern_first or pattern_second or pattern_third:
            pattern_computed = pattern_first + pattern_second + pattern_third
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + str(first) + SPLIT_CHAR + \
                str(second) + SPLIT_CHAR + str(third) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen

    elif instr_parts[0] == "MULMOD":
        if len(stack) < 3:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)
        third = stack.pop(0)

        if third == 0 or third == 1 or first == 0 or second == 0:
            computed = 0
        elif isAllReal(first, second, third):
            computed = (first * second) % third
        else:
            if isAllReal(first, second):
                computed = "(%d MULMOD %s)" % (first + second, third)
            else:
                computed = "((%s * %s) MULMOD %s)" % (str(first), str(second),
                                                      str(third))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_third = origin_pattern_stack.pop(0)
        origin_computed = "mulmod(%s, %s)" % (str(origin_first), str(origin_second), str(origin_third))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        pattern_third = pattern_stack.pop(0)
        if pattern_first or pattern_second or pattern_third:
            pattern_computed = pattern_first + pattern_second + pattern_third
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + str(first) + SPLIT_CHAR + \
                str(second) + SPLIT_CHAR + str(third) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    elif instr_parts[0] == "EXP":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        base = stack.pop(0)
        exponent = stack.pop(0)

        if base == 1 or exponent == 0:
            computed = 1
        elif exponent == 1:
            computed = base
        elif isAllReal(base, exponent):
            if exponent >= 0:
                computed = pow(base, exponent, 2**256)
            else:
                computed = 0
            # computed = pow(base, exponent) % 2**256
        else:
            computed = "(%s ** %s)" % (str(base), str(exponent))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "exp(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + str(base) + SPLIT_CHAR + \
                str(exponent) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen

    elif instr_parts[0] == "SIGNEXTEND":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if isAllReal(first, second):
            if first >= 32 or first < 0:
                computed = second
            else:
                signbit_index_from_right = 8 * first + 7
                if second & (1 << signbit_index_from_right):
                    computed = second | (2**256 -
                                         (1 << signbit_index_from_right))
                else:
                    computed = second & ((1 << signbit_index_from_right) - 1)
        else:
            computed = "(%s SIGNEXTEND %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "signextend(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    #
    #  10s: Comparison and Bitwise Logic Operations
    #
    elif instr_parts[0] == "LT":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if isAllReal(first, second):
            first = to_unsigned(first)
            second = to_unsigned(second)
            if first < second:
                computed = 1
            else:
                computed = 0
        else:
            computed = "(%s < %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "lt(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # 如果参数有一个为零，记录另外一个非零参数
        if isReal(first) and first == 0:
            params.lt_in_path.append(str(origin_second))
        if isReal(second) and second == 0:
            params.lt_in_path.append(str(origin_first))

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        pattern_stack.insert(0, [])
        # added by heppen

    elif instr_parts[0] == "GT":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if isAllReal(first, second):
            first = to_unsigned(first)
            second = to_unsigned(second)
            if first > second:
                computed = 1
            else:
                computed = 0
        else:
            computed = "(%s > %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "gt(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # 如果参数有一个为零，记录另外一个非零参数
        if isReal(first) and first == 0:
            params.gt_in_path.append(str(origin_second))
        if isReal(second) and second == 0:
            params.gt_in_path.append(str(origin_first))

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        pattern_stack.insert(0, [])
        # added by heppen
    elif instr_parts[0] == "SLT":  # Not fully faithful to signed comparison
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if isAllReal(first, second):
            first = to_signed(first)
            second = to_signed(second)
            if first < second:
                computed = 1
            else:
                computed = 0
        else:
            computed = "(%s < %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "slt(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        pattern_stack.insert(0, [])
        # added by heppen
    elif instr_parts[0] == "SGT":  # Not fully faithful to signed comparison
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if isAllReal(first, second):
            first = to_signed(first)
            second = to_signed(second)
            if first > second:
                computed = 1
            else:
                computed = 0
        else:
            computed = "(%s > %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "sgt(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        pattern_stack.insert(0, [])
        # added by heppen
    elif instr_parts[0] == "EQ":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if isAllReal(first, second):
            if first == second:
                computed = 1
            else:
                computed = 0
        else:
            computed = "(%s == %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "eq(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        if str(origin_first) in addrs_in_and or str(origin_second) in addrs_in_and:
            params.eq_in_path.append(str(origin_first))
            params.eq_in_path.append(str(origin_second))

        # 如果参数有一个为零，记录另外一个非零参数
        if isReal(first) and first == 0:
            params.eq_in_path.append(str(origin_second))
        if isReal(second) and second == 0:
            params.eq_in_path.append(str(origin_first))

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        pattern_stack.insert(0, pattern_first + pattern_second)
    elif instr_parts[0] == "ISZERO":
        # Tricky: this instruction works on both boolean and integer,
        # when we have a symbolic expression, type error might occur
        # Currently handled by try and catch
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        if isReal(first):
            if first == 0:
                computed = 1
            else:
                computed = 0
        else:
            computed = "(%s == 0)" % first
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_computed = "iszero(%s)" % (str(origin_first))
        origin_pattern_stack.insert(0, origin_computed)

        # 如果当前块的op中有call，则不将iszero数据纳入
        # 因为addr.transfer(value)操作会判断value是否为零
        try:
            block_ins = vertices[start].get_instructions()
        except KeyError:
            return ["ERROR"]
        if "CALL " not in block_ins:
            params.iszero_in_path.append(str(origin_first))

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_stack.insert(0, pattern_first)
    elif instr_parts[0] == "AND":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)

        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        address_mask = eval("0xffffffffffffffffffffffffffffffffffffffff")
        # 如果掩码是对应的地址掩码，则认为是一个新地址
        # 如果如果上一个记录
        origin_computed = ""
        if first == address_mask:
            first = hex(first)
            computed = second
            origin_computed = origin_second
            pattern_computed = [len(opcode_list)]
            if str(second) not in addrs_in_and:
                if isReal(second):
                    if len(str(second)) > 10:
                        # print origin_second  #debug
                        addrs_in_and.append(str(origin_second))

                else:
                    # print origin_second  #debug
                    addrs_in_and.append(str(origin_second))
        elif second == address_mask:
            second = hex(second)
            computed = first
            origin_computed = origin_first
            pattern_computed = [len(opcode_list)]
            if str(first) not in addrs_in_and:
                if isReal(first):
                    if len(str(first)) > 10:
                        # print origin_first  # debug
                        addrs_in_and.append(str(origin_first))

                else:
                    # print origin_first  # debug
                    addrs_in_and.append(str(origin_first))
        elif isAllReal(first, second):
            computed = first & second
            pattern_computed = []
        else:
            # 如果操作数是和地址相关
            if pattern_first or pattern_second:  # 两个操作数都和地址相关
                # 合并两个操作序列
                pattern_computed = pattern_first + \
                    pattern_second + [len(opcode_list)]
            else:
                pattern_computed = []
            if isReal(first):
                computed = "(%s & %s)" % (hex(first), str(second))
                first = hex(first)
            elif isReal(second):
                computed = "(%s & %s)" % (str(first), hex(second))
                second = hex(second)
            else:
                computed = "(%s & %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        if (origin_computed == ""):
            origin_computed = "and(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # 更新opcode_list和pattern_stack
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append("AND" + opParams + ins_pc)

    elif instr_parts[0] == "OR":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if first == 0:
            computed = second
        elif second == 0:
            computed = first
        elif isAllReal(first, second):
            computed = first | second
        else:
            computed = "(%s | %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "or(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen

    elif instr_parts[0] == "XOR":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        second = stack.pop(0)

        if isAllReal(first, second):
            computed = first ^ second
        else:
            computed = "(%s ^ %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "xor(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)
        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen
    elif instr_parts[0] == "NOT":
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)

        if isReal(first):
            computed = (~first) & UNSIGNED_BOUND_NUMBER
        else:
            computed = "(~%s)" % str(first)
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_computed = "not(%s)" % (str(origin_first))
        origin_pattern_stack.insert(0, origin_computed)
        # added by heppen
        pattern_first = pattern_stack.pop(0)
        if pattern_first and str(computed) != str(first):
            pattern_computed = pattern_first + [len(opcode_list)]
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + str(first) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen

    elif instr_parts[0] == "BYTE":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        first = stack.pop(0)
        byte_index = 32 - first - 1
        second = stack.pop(0)

        if isAllReal(first, second):
            if first >= 32 or first < 0:
                computed = 0
            else:
                computed = second & (255 << (8 * byte_index))
                computed = computed >> (8 * byte_index)
        else:
            computed = "(%s BYTE %s)" % (str(first), str(second))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "byte(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opParams = SPLIT_CHAR + \
                str(first) + SPLIT_CHAR + str(second) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen

    elif instr_parts[0] == "SHL":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        shift = stack.pop(0)
        value = stack.pop(0)
        if shift == 0:
            computed = value
        elif isReal(shift) and shift > 256:
            computed = 0
        elif isAllReal(shift, value):
            computed = (value << shift) % 2**256
        else:
            computed = "%s << %s" % (str(value), str(shift))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "shl(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opparams = SPLIT_CHAR + \
                str(shift) + SPLIT_CHAR + str(value) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opparams + ins_pc)

    elif instr_parts[0] == "SHR":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        shift = stack.pop(0)
        value = stack.pop(0)
        if shift == 0:
            computed = value
        elif isReal(shift) and shift > 256:
            computed = 0
        elif isAllReal(shift, value):
            computed = value >> shift
        else:
            computed = "%s >> %s" % (str(value), str(shift))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "shr(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opparams = SPLIT_CHAR + \
                str(shift) + SPLIT_CHAR + str(value) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opparams + ins_pc)

    elif instr_parts[0] == "SAR":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        shift = stack.pop(0)
        value = stack.pop(0)
        if shift == 0:
            computed = value
        elif isReal(shift) and shift > 256:
            computed = 0
        elif isAllReal(shift, value):
            computed = value >> shift
        else:
            computed = "%s >> %s" % (str(value), str(shift))
        stack.insert(0, computed)

        # 未优化表达式
        origin_first = origin_pattern_stack.pop(0)
        origin_second = origin_pattern_stack.pop(0)
        origin_computed = "sar(%s, %s)" % (str(origin_first), str(origin_second))
        origin_pattern_stack.insert(0, origin_computed)

        pattern_first = pattern_stack.pop(0)
        pattern_second = pattern_stack.pop(0)
        if pattern_first or pattern_second:
            pattern_computed = pattern_first + pattern_second
            pattern_computed.append(len(opcode_list))
        else:
            pattern_computed = []
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opparams = SPLIT_CHAR + \
                str(shift) + SPLIT_CHAR + str(value) + SPLIT_CHAR
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opparams + ins_pc)
    #
    # 20s: SHA3
    #
    elif instr_parts[0] == "SHA3":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        s0 = stack.pop(0)
        s1 = stack.pop(0)

        # added by heppen
        new_var_name = gen.gen_sha3_var(s0, s1, mem)
        # if methodid == TRANSFER_METHOD_ID:
        #     print mem
        # new_var = BitVec(new_var_name, 256)
        # path_conditions_and_vars[new_var_name] = new_var
        # stack.insert(0, new_var)
        stack.insert(0, new_var_name)

        # 未优化表达式
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_computed = gen.gen_sha3_origin_var(s0, s1, origin_pattern_mem)
        origin_pattern_stack.insert(0, origin_computed)

        # added by heppen
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_computed = []
        if isAllReal(s0, s1):
            size = s1 / 32
            memory_content = []
            opParams = SPLIT_CHAR
            for i in range(size):
                # 如果memory中的offset处没有值
                if int(s0) + i * 32 not in pattern_memory:
                    memory_content = []
                    break
                memory_content += pattern_memory[int(s0) + i * 32]

                opParams += str(mem[int(s0) + i * 32])
                opParams += SPLIT_CHAR
            if memory_content:
                pattern_computed = memory_content + [len(opcode_list)]
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            ins_pc = str(global_state["pc"])
            opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # added by heppen

    #
    # 30s: Environment Information
    #
    elif instr_parts[0] == "ADDRESS":
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, path_conditions_and_vars["Ia"])

        # 未优化表达式
        origin_pattern_stack.insert(0, "Ia")

        # added by heppen
        pattern_stack.insert(0, [])

    elif instr_parts[0] == "BALANCE":
        # print 'Balance'
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        address = stack.pop(0)
        pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        # if isReal(address) and global_params.USE_GLOBAL_BLOCKCHAIN:
        # new_var = data_source.getBalance(address)
        # else:
        new_var_name = gen.gen_balance_var()
        # if new_var_name in path_conditions_and_vars:
        #     new_var = path_conditions_and_vars[new_var_name]
        # else:
        #     new_var = BitVec(new_var_name, 256)
        #     path_conditions_and_vars[new_var_name] = new_var
        if isReal(address):
            hashed_address = "concrete_address_" + str(address)
        else:
            hashed_address = str(address)
        global_state["balance"][hashed_address] = new_var_name
        stack.insert(0, new_var_name)

        # 未优化表达式
        origin_pattern_stack.insert(0, new_var_name)
        # added by heppen
        pattern_stack.insert(0, [])
    elif instr_parts[0] == "CALLER":  # get msg sender address
        # that is directly responsible for this execution
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["sender_address"])

        # 未优化表达式
        origin_pattern_stack.insert(0, global_state["sender_address"])

        # added by heppen
        pattern_stack.insert(0, [len(opcode_list)])
        opcode_list.append(instr_parts[0] + SPLIT_CHAR +
                           str(global_state["sender_address"]))
    elif instr_parts[0] == "ORIGIN":  # get execution origination address
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["origin"])

        origin_pattern_stack.insert(0, global_state["origin"])

        # added by heppen
        pattern_stack.insert(0, [])
    elif instr_parts[0] == "CALLVALUE":  # get value of this transaction
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["value"])

        origin_pattern_stack.insert(0, global_state["value"])

        pattern_stack.insert(0, [])  # added by heppen
    # new opcode
    elif instr_parts[0] == "RETURNDATACOPY":
        if len(stack) < 3:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] += 1
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)

        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)

        # added by heppen
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)

    elif instr_parts[0] == "RETURNDATASIZE":
        global_state["pc"] += 1
        new_var_name = gen.gen_arbitrary_var()
        # new_var = BitVec(new_var_name, 256)
        stack.insert(0, new_var_name)

        origin_pattern_stack.insert(0, new_var_name)

        pattern_stack.insert(0, [])  # added by heppen
    elif instr_parts[0] == "STATICCALL":
        if len(stack) < 6:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] += 1
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)

        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)

        new_var_name = gen.gen_arbitrary_var()
        # new_var = BitVec(new_var_name, 256)
        stack.insert(0, new_var_name)

        origin_pattern_stack.insert(0, new_var_name)

        pattern_stack.insert(0, [])  # added by heppen
    # new opcode
    elif instr_parts[0] == "CALLDATALOAD":  # from input data from environment
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        position = stack.pop(0)

        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)
        new_var_name = gen.gen_load_data_var(position)

        # if new_var_name in path_conditions_and_vars:
        #     new_var = path_conditions_and_vars[new_var_name]
        # else:
        #     new_var = BitVec(new_var_name, 256)
        #     path_conditions_and_vars[new_var_name] = new_var
        # stack.insert(0, new_var)
        stack.insert(0, new_var_name)

        origin_pattern_stack.insert(0, new_var_name)

        # 如果是vyper的话，需要从calldataload开始跟踪
        # if isVyper:
        #     pattern_stack.insert(0, [len(opcode_list)])
        #     opParams = SPLIT_CHAR + str(position) + SPLIT_CHAR
        #     ins_pc = str(global_state["pc"])
        #     opcode_list.append(instr_parts[0] + opParams + ins_pc)
        # else:
        pattern_stack.insert(0, [])
    elif instr_parts[0] == "CALLDATASIZE":
        global_state["pc"] = global_state["pc"] + 1
        new_var_name = gen.gen_data_size()
        # if new_var_name in path_conditions_and_vars:
        #     new_var = path_conditions_and_vars[new_var_name]
        # else:
        #     new_var = BitVec(new_var_name, 256)
        #     path_conditions_and_vars[new_var_name] = new_var
        stack.insert(0, new_var_name)

        origin_pattern_stack.insert(0, new_var_name)

        pattern_stack.insert(0, [])

    elif instr_parts[0] == "CALLDATACOPY":  # Copy input data to memory
        if len(stack) < 3:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        mem_offset = stack.pop(0)  # memory offset
        data_offset = stack.pop(0)  # data offset
        length = stack.pop(0)  # length

        # debug
        # print mem_offset, data_offset, length

        # 针对vyper的参数可能由calldatacopy而来设计
        # if isVyper and isAllReal(mem_offset, data_offset, length):
        #     num = length / 32
        #     for i in range(num):
        #         mem[mem_offset + i * 32] = "msg(" + str(data_offset + i*32) + ")"
        #         origin_pattern_mem[mem_offset + i * 32] = "msg(" + str(data_offset + i*32) + ")"

        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)

    elif instr_parts[0] == "CODESIZE":
        if c_name.endswith('.disasm'):
            evm_file_name = c_name[:-7]
        else:
            evm_file_name = c_name
        with open(evm_file_name, 'r') as evm_file:
            evm = evm_file.read()[:-1]
            code_size = len(evm) / 2
            stack.insert(0, code_size)

            origin_pattern_stack.insert(0, code_size)

            pattern_stack.insert(0, [])
    elif instr_parts[0] == "CODECOPY":
        if len(stack) < 3:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        mem_location = stack.pop(0)
        code_from = stack.pop(0)
        no_bytes = stack.pop(0)

        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)

        if isAllReal(mem_location, code_from, no_bytes):
            if c_name.endswith('.disasm'):
                evm_file_name = c_name[:-7]
            else:
                evm_file_name = c_name
            with open(evm_file_name, 'r') as evm_file:
                evm = evm_file.read()[:-1]
                start = code_from * 2
                end = start + no_bytes * 2
                code = evm[start:end]
            if code:
                mem[mem_location] = int(code, 16)
                # 未优化表达式处理
                origin_pattern_mem[mem_location] = int(code, 16)
        else:
            new_var_name = gen.gen_code_var("Ia", code_from, no_bytes)
            # if new_var_name in path_conditions_and_vars:
            #     new_var = path_conditions_and_vars[new_var_name]
            # else:
            #     new_var = BitVec(new_var_name, 256)
            #     path_conditions_and_vars[new_var_name] = new_var

            mem.clear()  # very conservative
            mem[str(mem_location)] = new_var_name

            origin_pattern_mem.clear()
            origin_pattern_mem[str(mem_location)] = new_var_name
    elif instr_parts[0] == "GASPRICE":
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["gas_price"])

        origin_pattern_stack.insert(0, global_state["gas_price"])

        pattern_stack.insert(0, [])  # added by heppen
    elif instr_parts[0] == "EXTCODESIZE":
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        address = stack.pop(0)

        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)

        new_var_name = gen.gen_code_size_var(address)
        # if new_var_name in path_conditions_and_vars:
        #     new_var = path_conditions_and_vars[new_var_name]
        # else:
        #     new_var = BitVec(new_var_name, 256)
        #     path_conditions_and_vars[new_var_name] = new_var
        stack.insert(0, new_var_name)

        origin_pattern_stack.insert(0, new_var_name)

        pattern_stack.insert(0, [])

    elif instr_parts[0] == "EXTCODECOPY":
        if len(stack) < 4:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        address = stack.pop(0)
        mem_location = stack.pop(0)
        code_from = stack.pop(0)
        no_bytes = stack.pop(0)

        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        new_var_name = gen.gen_code_var(address, code_from, no_bytes)
        # if new_var_name in path_conditions_and_vars:
        #     new_var = path_conditions_and_vars[new_var_name]
        # else:
        #     new_var = BitVec(new_var_name, 256)
        #     path_conditions_and_vars[new_var_name] = new_var

        origin_pattern_mem.clear()  # very conservative
        origin_pattern_mem[str(mem_location)] = new_var_name

        mem.clear()  # very conservative
        mem[str(mem_location)] = new_var_name
    #
    #  40s: Block Information
    #
    elif instr_parts[0] == "BLOCKHASH":  # information from block header
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        stack.pop(0)

        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)
        new_var_name = "IH_blockhash"
        # if new_var_name in path_conditions_and_vars:
        #     new_var = path_conditions_and_vars[new_var_name]
        # else:
        #     new_var = BitVec(new_var_name, 256)
        #     path_conditions_and_vars[new_var_name] = new_var
        stack.insert(0, new_var_name)

        origin_pattern_stack.insert(0, new_var_name)

        pattern_stack.insert(0, [])
    elif instr_parts[0] == "COINBASE":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentCoinbase"])

        origin_pattern_stack.insert(0, global_state["currentCoinbase"])

        pattern_stack.insert(0, [])
    elif instr_parts[0] == "TIMESTAMP":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentTimestamp"])

        origin_pattern_stack.insert(0, global_state["currentTimestamp"])

        pattern_stack.insert(0, [])
    elif instr_parts[0] == "NUMBER":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentNumber"])

        origin_pattern_stack.insert(0, global_state["currentNumber"])

        pattern_stack.insert(0, [])
    elif instr_parts[0] == "DIFFICULTY":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentDifficulty"])

        origin_pattern_stack.insert(0, global_state["currentDifficulty"])

        pattern_stack.insert(0, [])
    elif instr_parts[0] == "GASLIMIT":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentGasLimit"])

        origin_pattern_stack.insert(0, global_state["currentGasLimit"])

        pattern_stack.insert(0, [])

    #
    #  50s: Stack, Memory, Storage, and Flow Information
    #
    elif instr_parts[0] == "POP":
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        stack.pop(0)
        origin_pattern_stack.pop(0)
        pattern_stack.pop(0)
    elif instr_parts[0] == "MLOAD":
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        address = stack.pop(0)

        origin_address = origin_pattern_stack.pop(0)

        # added by heppen
        # new_var_name = ""
        if address in mem:
            value = mem[address]
            stack.insert(0, value)
        elif str(address) in mem:
            value = mem[str(address)]
            stack.insert(0, value)
        else:
            new_var_name = gen.gen_mem_var(address)
            # origin_name = "mem(" + origin_address + ")"
            # if new_var_name in path_conditions_and_vars:
            #     new_var = path_conditions_and_vars[new_var_name]
            # else:
            #     new_var = BitVec(new_var_name, 256)
            #     path_conditions_and_vars[new_var_name] = new_var
            stack.insert(0, new_var_name)

            # origin_pattern_stack.insert(0, new_var_name)
            if isReal(address):
                mem[address] = new_var_name
                # origin_pattern_mem[address] = origin_name
            else:
                mem[str(address)] = new_var_name
                # origin_pattern_mem[str(address)] = origin_name

        if address in origin_pattern_mem:
            v = origin_pattern_mem[address]
            origin_pattern_stack.insert(0, v)
        elif str(address) in origin_pattern_mem:
            v = origin_pattern_mem[str(address)]
            origin_pattern_stack.insert(0, v)
        else:
            new_name = "mem(" + str(origin_address) + ")"
            if isReal(address):
                origin_pattern_mem[address] = new_name
            else:
                origin_pattern_mem[str(address)] = new_name
            origin_pattern_stack.insert(0, new_name)


        # added by heppen
        pattern_stack.pop(0)
        pattern_computed = []
        # 要求地址是实数，并且这个地址在memory中有存在
        if isReal(address) and int(address) in pattern_memory:
            pattern_computed = pattern_memory[int(address)]
        pattern_stack.insert(0, pattern_computed)
        if pattern_computed:
            opcode_str = instr_parts[0] + SPLIT_CHAR + \
                str(stack[0]) + SPLIT_CHAR + str(global_state["pc"])
            opcode_list.append(opcode_str)
        # added by heppen
    elif instr_parts[0] == "MSTORE":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        stored_address = stack.pop(0)
        stored_value = stack.pop(0)

        origin_stored_address = origin_pattern_stack.pop(0)
        origin_stored_value = origin_pattern_stack.pop(0)

        if isReal(stored_address):
            mem[stored_address] = stored_value
            origin_pattern_mem[stored_address] = origin_stored_value
        else:
            mem[str(stored_address)] = stored_value
            origin_pattern_mem[str(stored_address)] = origin_stored_value

        # added by heppen
        pattern_stack.pop(0)
        pattern_value = pattern_stack.pop(0)
        # 如果是vyper合约，从mstore开始跟踪，要求mstore的值为cload
        # if isVyper and (re.match(r"Cload\(\d+\)", str(stored_value)) or "msg" in str(stored_value)):
        #     if origin_stored_value not in addrs_in_and and not origin_stored_value.isdigit():
        #         # print origin_stored_value  # debug
        #         addrs_in_and.append(str(origin_stored_value))
        #         # print addrs_in_and
        #     pattern_value = [len(opcode_list)]
        #     opParams = SPLIT_CHAR + \
        #         str(stored_address) + SPLIT_CHAR + \
        #         str(stored_value) + SPLIT_CHAR + str(global_state["pc"])
        #     opcode_list.append(instr_parts[0] + opParams)
        if isReal(stored_address):
            pattern_memory[int(stored_address)] = pattern_value
    elif instr_parts[0] == "MSTORE8":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        stored_address = stack.pop(0)
        temp_value = stack.pop(0)

        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)
        pattern_stack.pop(0)
    elif instr_parts[0] == "SLOAD":
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        address = stack.pop(0)
        # address_str = str(address).replace("Cload(4)", "x")
        # if methodid == '0x70a08231':
        #     if address_str not in balance_of_addrs:
        #         if "sha3" in address_str:
        #             balance_of_addrs.append(address_str)

        pattern_address = pattern_stack.pop(0)

        origin_pattern_address = origin_pattern_stack.pop(0)

        if isReal(address) and address in global_state["Ia"]:
            value = global_state["Ia"][address]
            stack.insert(0, value)
        else:
            if str(address) in global_state["Ia"]:
                value = global_state["Ia"][str(address)]
                stack.insert(0, value)
            else:
                if is_expr(address):
                    address = simplify(address)
                else:
                    new_var_name = gen.gen_owner_store_var(address)
                # if new_var_name in path_conditions_and_vars:
                #     new_var = path_conditions_and_vars[new_var_name]
                # else:
                #     new_var = BitVec(new_var_name, 256)
                #     path_conditions_and_vars[new_var_name] = new_var
                stack.insert(0, new_var_name)
                if isReal(address):
                    global_state["Ia"][address] = new_var_name
                else:
                    global_state["Ia"][str(address)] = new_var_name

        # print "sload:", origin_pattern_address
        if origin_pattern_address in origin_pattern_storage:
            o_value = origin_pattern_storage[origin_pattern_address]
            origin_pattern_stack.insert(0, o_value)
        else:
            new_name = gen.gen_owner_store_var(origin_pattern_address)
            origin_pattern_stack.insert(0, new_name)
            origin_pattern_storage[origin_pattern_address] = new_name

        # added by heppen
        # 如果sload的参数和地址相关，说明下一个存入pattern_stack中的值应该是增加sload这个当前opcode的
        # 无须考虑sload出来的值到底和地址有没有关
        if pattern_address:
            pattern_stack.insert(0, pattern_address + [len(opcode_list)])
            opcode_str = instr_parts[0] + SPLIT_CHAR + \
                str(address) + SPLIT_CHAR + str(global_state["pc"])
            opcode_list.append(opcode_str)
        # 如果sload的参数和地址无关，说明下一个存入pattern_stack中的值就和地址无关
        else:
            pattern_stack.insert(0, [])

    elif instr_parts[0] == "SSTORE":
        global g_sstore  # capture all sstore info.
        global event_addrs
        global transfer_sstore_addresses
        global transferfrom_sstore_addresses
        global sstore_addresses
        global sstore_pc
        # global out_block
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        stored_address = stack.pop(0)
        stored_value = stack.pop(0)

        pattern_address = pattern_stack.pop(0)
        pattern_value = pattern_stack.pop(0)

        origin_pattern_address = origin_pattern_stack.pop(0)
        origin_pattern_value = origin_pattern_stack.pop(0)

        # 存储当前函数内的sstore信息
        if "sha3" in str(origin_pattern_address):
            if str(origin_pattern_address) not in sstore_info:
                sstore_info[str(origin_pattern_address)] = [str(origin_pattern_value)]
            else:
                sstore_info[str(origin_pattern_address)].append(str(origin_pattern_value))
        origin_pattern_storage[str(origin_pattern_address)] = str(origin_pattern_value)

        # 存储sstore的key到对应path中
        if "sha3" in str(origin_pattern_address):
            params.sstore_info_in_path.append(str(origin_pattern_address))

        if not isinstance(stored_address, str):
            stored_address = str(stored_address)
        # change addr symbol to x.
        # modified_addr = modify_sstore_addr(stored_address, addrs_in_and)
        modified_addr = modify_sstore_addr(origin_pattern_address, addrs_in_and)
        # 保存每种pattern表达式对应的所有pc值
        if modified_addr not in sstore_pc:
            sstore_pc[modified_addr] = [global_state["pc"]]
        elif global_state["pc"] not in sstore_pc[modified_addr]:
            sstore_pc[modified_addr].append(global_state["pc"])

        addr_key = compact_string(str(stored_address))
        if (methodid == TRANSFER_METHOD_ID
                and addr_key not in transfer_sstore_addresses
                and pattern_address):
            transfer_sstore_addresses[addr_key] = []
            # 提取一个表达式对应的opcode序列
            for i in sorted(set(pattern_address)):
                addr_value = compact_string(str(opcode_list[i]))
                transfer_sstore_addresses[addr_key].append(addr_value)
        elif (methodid == TRANSFERFROM_METHOD_ID
              and addr_key not in transferfrom_sstore_addresses
              and pattern_address):
            transferfrom_sstore_addresses[addr_key] = []
            for i in sorted(set(pattern_address)):
                addr_value = compact_string(str(opcode_list[i]))
                transferfrom_sstore_addresses[addr_key].append(addr_value)
            # transferfrom_sstore_addresses[addr_key].append(global_state['pc'])
        if (methodid != "" and addr_key not in sstore_addresses
                and pattern_address):
            # 根据methodid来存储
            if methodid not in sstore_addresses:
                sstore_addresses[methodid] = {}
            method_sstore_addrs = sstore_addresses[methodid]
            method_sstore_addrs[addr_key] = []
            for i in sorted(set(pattern_address)):
                addr_value = compact_string(str(opcode_list[i]))
                method_sstore_addrs[addr_key].append(addr_value)
            # method_sstore_addrs[addr_key].append(global_state['pc'])

        if isReal(stored_address):
            # note that the stored_value could be unknown
            global_state["Ia"][stored_address] = stored_value
        else:
            # note that the stored_value could be unknown
            global_state["Ia"][str(stored_address)] = stored_value
        if pattern_address + pattern_value:
            pattern_storage[stored_address] = pattern_value + \
                pattern_address + [len(opcode_list)]
        else:
            pattern_storage[stored_address] = []
        if pattern_value or pattern_address:
            opcode_str = instr_parts[0] + SPLIT_CHAR + str(
                stored_address) + SPLIT_CHAR + str(
                    stored_value) + SPLIT_CHAR + str(global_state["pc"])
            opcode_str.replace("\n", " ")
            opcode_list.append(opcode_str)
    elif instr_parts[0] == "JUMP":
        if not stack:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        target_address = stack.pop(0)
        origin_pattern_stack.pop(0)
        pattern_stack.pop(0)
        if isSymbolic(target_address):
            # print mem
            # print start, methodid
            raise TypeError("[jump] Target address must be an integer")
        vertices[start].set_jump_target(target_address)
        if target_address not in edges[start]:
            edges[start].append(target_address)
    elif instr_parts[0] == "JUMPI":
        # We need to prepare two branches
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        target_address = stack.pop(0)

        if isSymbolic(target_address):
            raise TypeError("Target address " + str(target_address) + " must be an integer")
        vertices[start].set_jump_target(target_address)
        flag = stack.pop(0)
        if isReal(flag):
            params.jumpi_flag = flag
        else:
            params.jumpi_flag = -1

        origin_pattern_stack.pop(0)
        origin_flag = origin_pattern_stack.pop(0)
        # print "jumpi flag:", origin_flag  # debug
        params.jumpi_flags_in_path.append(str(origin_flag))

        pattern_stack.pop(0)
        pattern_stack.pop(0)
        if target_address not in edges[start]:  # ?
            edges[start].append(target_address)
    elif instr_parts[0] == "PC":
        stack.insert(0, global_state["pc"])
        global_state["pc"] = global_state["pc"] + 1

        origin_pattern_stack.insert(0, global_state["pc"])

        pattern_stack.insert(0, [])
    elif instr_parts[0] == "MSIZE":
        global_state["pc"] = global_state["pc"] + 1
        msize = 32 * global_state["miu_i"]
        stack.insert(0, msize)

        origin_pattern_stack.insert(0, msize)

        pattern_stack.insert(0, [])
    elif instr_parts[0] == "GAS":
        # In general, we do not have this precisely. It depends on both
        # the initial gas and the amount has been depleted
        # we need o think about this in the future, in case precise gas
        # can be tracked
        global_state["pc"] = global_state["pc"] + 1
        new_var_name = gen.gen_gas_var()
        # new_var = BitVec(new_var_name, 256)
        # path_conditions_and_vars[new_var_name] = new_var
        stack.insert(0, new_var_name)

        origin_pattern_stack.insert(0, new_var_name)
        pattern_stack.insert(0, [])
    elif instr_parts[0] == "JUMPDEST":
        # Literally do nothing
        global_state["pc"] = global_state["pc"] + 1
    #
    #  60s & 70s: Push Operations
    #
    elif instr_parts[0].startswith('PUSH', 0):  # this is a push instruction
        position = int(instr_parts[0][4:], 10)  # 取PUSH后的数字，确定是哪一种PUSH
        # 增加对应PC值
        global_state["pc"] = global_state["pc"] + 1 + position
        pushed_value = -1
        if instr_parts[1]:
            pushed_value = int(instr_parts[1], 16)  # 解析十六进制的value为十进制
        stack.insert(0, pushed_value)  # stack的元素是不定长的
        # if global_params.UNIT_TEST == 3:  # test evm symbolic
        #     stack[0] = BitVecVal(stack[0], 256)

        origin_pattern_stack.insert(0, pushed_value)

        # 和地址无关，直接压空数组入栈 -- added by heppen
        pattern_stack.insert(0, [])

    #
    #  80s: Duplication Operations
    #
    elif instr_parts[0].startswith("DUP", 0):
        global_state["pc"] = global_state["pc"] + 1
        position = int(instr_parts[0][3:], 10) - 1

        if len(stack) <= position:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        duplicate = stack[position]
        stack.insert(0, duplicate)

        origin_duplicate = origin_pattern_stack[position]
        origin_pattern_stack.insert(0, origin_duplicate)

        pattern_duplicate = pattern_stack[position]
        pattern_stack.insert(0, pattern_duplicate)
    #
    #  90s: Swap Operations
    #
    elif instr_parts[0].startswith("SWAP", 0):
        global_state["pc"] = global_state["pc"] + 1
        position = int(instr_parts[0][4:], 10)
        if len(stack) <= position:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        temp = stack[position]
        stack[position] = stack[0]
        stack[0] = temp

        origin_temp = origin_pattern_stack[position]
        origin_pattern_stack[position] = origin_pattern_stack[0]
        origin_pattern_stack[0] = origin_temp

        pattern_temp = pattern_stack[position]
        pattern_stack[position] = pattern_stack[0]
        pattern_stack[0] = pattern_temp
    #
    #  a0s: Logging Operations
    #
    elif instr_parts[0] in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
        global event_params
        # global erc1155_event_params
        # global is_erc1155
        global_state["pc"] = global_state["pc"] + 1
        # We do not simulate these log operations

        topics = []  # collect
        pattern_topics = []
        origin_topics = []

        num_of_pops = 2 + int(instr_parts[0][3:])
        while num_of_pops > 0:  # 根据不同的LOG数pop不同的数量的元素
            topic_temp = stack.pop(0)
            pattern_topic_temp = pattern_stack.pop(0)
            origin_topic_temp = origin_pattern_stack.pop(0)

            num_of_pops -= 1

            topics.append(topic_temp)  #
            pattern_topics.append(pattern_topic_temp)
            origin_topics.append(origin_topic_temp)

        # if methodid == "0x729ad39e":  # debug
        #     print "topic:", topics
        #     print "pattern_topics:", origin_topics

        # 获取标准Transfer事件中的value值
        offset = topics.pop(0)
        length = topics.pop(0)
        log_topic = topics.pop(0)

        pattern_offset = pattern_topics.pop(0)
        pattern_length = pattern_topics.pop(0)
        pattern_log_topic = pattern_topics.pop(0)

        origin_offset = origin_topics.pop(0)
        origin_length = origin_topics.pop(0)
        origin_log_topic = origin_topics.pop(0)

        # 标准Transfer事件中的三个参数
        # event_params = []  # 依次是from/to/value
        # print "method in log:", methodid
        # print "log:", log_topic
        if instr_parts[0] == "LOG3" and isReal(log_topic) and hex(log_topic) == ("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efL"):
            # if methodid == "0xa9059cbb":
            #     print "LOG block:", start
            # print "topics", topics, instr_parts
            # if methodid == TRANSFER_METHOD_ID:
            # if not params.sstore_info_in_path and methodid not in g_fake_notice:
            #     g_fake_notice.append(methodid)
            from_addr = str(topics.pop(0))
            to_addr = str(topics.pop(0))
            # event_params.append(from_addr)
            # event_params.append(to_addr)
            # print "enter Transfer"  # debug

            pattern_from_addr = str(pattern_topics.pop(0))
            pattern_to_addr = str(pattern_topics.pop(0))

            origin_from_addr = str(origin_topics.pop(0))
            origin_to_addr = str(origin_topics.pop(0))

            # 记录当前路径的event信息
            event_params.append(origin_from_addr)
            event_params.append(origin_to_addr)
            params.event_info_in_path.append(origin_from_addr)
            params.event_info_in_path.append(origin_to_addr)
            # print "origin_from:", origin_from_addr, "from:", from_addr  # debug
            if isAllReal(offset, length):
                n = length / 32
                for i in range(n):
                    if (offset + 32*i) not in origin_pattern_mem:
                        continue
                    event_params.append(str(origin_pattern_mem[offset + 32*i]))
                    params.event_info_in_path.append(str(origin_pattern_mem[offset + 32*i]))
                    # if (offset + 32 * i) not in mem or (
                    #         mem[offset + 32 * i] in values_in_transfer_event):
                    #     continue
                    # values_in_transfer_event.append(mem[offset + 32 * i])
            elif offset in origin_pattern_mem and origin_pattern_mem[offset] not in values_in_transfer_event:
                event_params.append(str(origin_pattern_mem[offset]))
                params.event_info_in_path.append(
                        str(origin_pattern_mem[offset]))
                # values_in_transfer_event.append(mem[offset])
        # ERC1155标准TransferSingle事件
        # if instr_parts[0] == "LOG4" and isReal(log_topic) and hex(log_topic) == ("0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62L"):
        #     # pprint.pprint(sstore_info)
        #     # if not params.sstore_info_in_path and methodid not in g_fake_notice:
        #     #     g_fake_notice.append(methodid)
        #     is_erc1155 = True
        #     erc1155_event_params = []
        #     topics.pop(0)
        #     topics.pop(0)
        #     topics.pop(0)

        #     pattern_topics.pop(0)
        #     pattern_topics.pop(0)
        #     pattern_topics.pop(0)

        #     p1 = origin_topics.pop(0)
        #     p2 = origin_topics.pop(0)
        #     p3 = origin_topics.pop(0)
        #     # TODO: erc1155判断fake notification
        #     erc1155_event_params.append(str(p1))
        #     erc1155_event_params.append(str(p2))
        #     erc1155_event_params.append(str(p3))
        #     if isAllReal(offset, length):
        #         n = length / 32
        #         for i in range(n):
        #             if (offset + 32*i) not in origin_pattern_mem:
        #                 continue
        #             erc1155_event_params.append(
        #                     str(origin_pattern_mem[offset + 32*i]))
        #     elif (offset in origin_pattern_mem and origin_pattern_mem[offset]
        #             not in values_in_transfer_event):
        #         erc1155_event_params.append(str(origin_pattern_mem[offset]))

    #
    #  f0s: System Operations
    #
    elif instr_parts[0] == "CREATE":
        if len(stack) < 3:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] += 1
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)

        origin_pattern_stack.pop(0)  # added by heppen
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)  # added by heppen
        pattern_stack.pop(0)
        pattern_stack.pop(0)

        new_var_name = gen.gen_arbitrary_var()
        # new_var = BitVec(new_var_name, 256)
        stack.insert(0, new_var_name)

        origin_pattern_stack.insert(0, new_var_name)

        pattern_stack.insert(0, [])

    elif instr_parts[0] == "CALL":
        if len(stack) < 7:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        stack.pop(0)
        to_addr = stack.pop(0)  # to_addr
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)

        # 记录当前路径是否有跨合约调用
        if str(to_addr) != 'Is' and str(to_addr) != 'Ia':
            try:
                pre_block_ins = vertices[params.pre_block].get_instructions()
            except KeyError:
                return ["ERROR"]
            # 根据上一block中是否有EXTCODESIZE来区分是跨合约调用，还是addr.transfer()
            if "EXTCODESIZE " in pre_block_ins:
                params.has_call_in_path = True

        new_var_name = gen.gen_arbitrary_var()  # by hao
        # new_var = BitVec(new_var_name, 256)  # by hao
        stack.insert(0, new_var_name)  # by hao

        origin_pattern_stack.pop(0)  # added by heppen
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.insert(0, new_var_name)  # by hao

        pattern_stack.pop(0)  # added by heppen
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.insert(0, [])

    elif instr_parts[0] == "CALLCODE":
        if len(stack) < 7:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        stack.pop(0)
        stack.pop(0)  # this is not used as recipient
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)

        # in the paper, it is shaky when the size of data output is
        # min of stack[6] and the | o |
        new_var_name = gen.gen_arbitrary_var()  # by hao
        # new_var = BitVec(new_var_name, 256)  # by hao
        stack.insert(0, new_var_name)  # by hao

        origin_pattern_stack.pop(0)  # added by heppen
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.insert(0, new_var_name)  # by hao

        pattern_stack.pop(0)  # added by heppen
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.insert(0, [])

    elif instr_parts[0] == "DELEGATECALL":
        if len(stack) < 6:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] += 1
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)
        stack.pop(0)

        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)
        pattern_stack.pop(0)

        new_var_name = gen.gen_arbitrary_var()
        # new_var = BitVec(new_var_name, 256)
        stack.insert(0, new_var_name)

        origin_pattern_stack.insert(0, new_var_name)

        pattern_stack.insert(0, [])

    elif instr_parts[0] == "RETURN" or instr_parts[0] == "REVERT":
        if len(stack) < 2:
            raise ValueError('[STACK underflow] block: %d, ins: %d' %
                             (start, global_state["pc"]))
        global_state["pc"] = global_state["pc"] + 1
        stack.pop(0)
        stack.pop(0)

        origin_pattern_stack.pop(0)
        origin_pattern_stack.pop(0)

        pattern_stack.pop(0)
        pattern_stack.pop(0)

        # if instr_parts[0] == "RETURN" and (methodid == TRANSFER_METHOD_ID or methodid == TRANSFERFROM_METHOD_ID or methodid == SAFE_TRANSFERFROM_METHOD_ID):
        #     if not sstore_info:
        #         print "FAKE DEPOSIT!", methodid
        #     else:
        #         out_block = params.pre_block
    elif instr_parts[0] == "SUICIDE":
        global_state["pc"] = global_state["pc"] + 1
        recipient = stack.pop(0)

        pattern_stack.pop(0)
        origin_pattern_stack.pop(0)
        transfer_amount = global_state["balance"]["Ia"]
        global_state["balance"]["Ia"] = 0
        if isReal(recipient):
            new_address_name = "concrete_address_" + str(recipient)
        else:
            new_address_name = gen.gen_arbitrary_address_var()
        old_balance_name = gen.gen_arbitrary_var()
        return

    else:
        if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
            log.critical("Unkown instruction: %s" % instr_parts[0])
            exit(UNKOWN_INSTRUCTION)
        raise Exception('UNKNOWN INSTRUCTION: ' + instr_parts[0])

    try:
        print_state(stack, mem, global_state)
    except Exception:
        pass


def write(path, mode, data):
    with open(path, mode) as f:
        f.write(data)
    f.close()


def detect_bugs():
    global results
    global source_map
    global visited_pcs
    global any_bug
    global exec_blocks
    global opcode_exectime
    global coverage

    if instructions:
        evm_code_coverage = float(len(visited_pcs)) / \
            len(instructions.keys()) * 100
        coverage = round(evm_code_coverage, 1)
        # for op in instructions.keys():
        # if op not in visited_pcs:
        #        print op
        opcost = {}
        sum_cost = 0
        # print len(opcode_exectime)
        for instr, costlist in opcode_exectime.items():
            sum_cost += sum(costlist)
            avg_cost = sum(costlist) / float(len(costlist))
            #  avg_cost = max(costlist)
            opcost[instr] = avg_cost
        opcost_sort = sorted(opcost.items(), key=lambda x: x[1])
        # for instr, avg_cost in opcost_sort:
        #     print instr, avg_cost, sum(opcode_exectime.get(instr)), len(
        #         opcode_exectime.get(instr))
        log.info("\t  EVM instr exec:  \t %s", sum_cost)
        log.info("\t  EVM code coverage:  \t %s%%",
                 round(evm_code_coverage, 1))
        log.info("\t  EVM blocks exec:  \t %s", exec_blocks)
        # log.info("\t  Method ABI info:  \t %s", method_abi['methods'])
        # log.info("\t  Method ABI event info:  \t %s\n", method_abi['event'])
        # log.info("\t  Method ABI sstore info:  \t %s\n", method_abi['sstore'])

        return True
    else:
        pass


def closing_message():
    global c_name_sol
    global resultsprint

    log.info("\t====== Analysis Completed ======")


def handler(signum, frame):
    if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
        exit(TIME_OUT)
    detect_bugs()
    write('coverage-report', 'a', 'Timeout!!!\n')
    raise Exception("timeout")


def main(contract, contract_sol, _source_map=None):
    global c_name
    global c_name_sol
    global source_map
    global g_sstore  # save all sstore information. by heppen
    global coverage  # get evm_code_coveray. by heppen
    global transfer_sstore_addresses
    global transferfrom_sstore_addresses
    global sstore_addresses
    global addrs_in_and
    global shift_bit
    global sstore_pc
    global two_match_pattern
    global method_match_pattern
    global event_match_pattern
    global no_match_pattern
    global is_infinite
    g_sstore = {}
    event_addrs = {}
    c_name = contract
    c_name_sol = contract_sol
    source_map = _source_map

    check_unit_test_file()
    initGlobalVars()
    start = time.time()
    signal.signal(signal.SIGALRM, handler)
    if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
        global_params.GLOBAL_TIMEOUT = global_params.GLOBAL_TIMEOUT_TEST
    signal.alarm(global_params.GLOBAL_TIMEOUT)
    try:
        build_cfg_and_analyze()
        # print "two_match_pattern:", two_match_pattern
        # print "method:", method_match_pattern
        # print "event:", event_match_pattern
        # print "noo:", no_match_pattern
        # 如果释放策略提前结束，执行原始符号执行
        # if (is_infinite or (not two_match_pattern and not method_match_pattern and not event_match_pattern and not no_match_pattern)):
        #     # print "is_infinite!!"  # debug
        #     g_sstore = {}
        #     event_addrs = {}
        #     c_name = contract
        #     c_name_sol = contract_sol
        #     source_map = _source_map

        #     check_unit_test_file()
        #     initGlobalVars()
        #     start = time.time()
        #     signal.signal(signal.SIGALRM, handler)
        #     if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
        #         global_params.GLOBAL_TIMEOUT = global_params.GLOBAL_TIMEOUT_TEST
        #     signal.alarm(global_params.GLOBAL_TIMEOUT)
        #     # atexit.register(closing_message)
        #     global_params.LOOP_LIMIT = 6
        #     build_cfg_and_analyze()

    except Exception as e:
        # print e.message, 2578
        log.info(e.message)
        if global_params.UNIT_TEST == 2 or global_params.UNIT_TEST == 3:
            log.exception(e)
            exit(EXCEPTION)
        traceback.print_exc()
        raise e
    atexit.register(closing_message)
    signal.alarm(0)

    detect_bugs()

    # 打印sstore的结果
    has_answer = False

    # global is_erc1155
    # if (is_erc1155):
    #     print "[erc1155]\n",
    # if g_fake_notice:
    #     print "fake notice:", g_fake_notice

    temp_pattern = []
    if (two_match_pattern):
        # print two_match_pattern
        temp_pattern = list(set(two_match_pattern))
        for p in set(two_match_pattern):
            # __import__('pprint').pprint(list(set(two_match_pattern)))
            restore_ds.init_reds()
            pc_str = ','.join(str(x) for x in sstore_pc[p])
            print "two:", p, "=>", restore_ds.get_ds(p, isVyper), "||", pc_str

    elif (method_match_pattern):
        temp_pattern = list(set(method_match_pattern))
        for p in set(method_match_pattern):
            restore_ds.init_reds()
            pc_str = ','.join(str(x) for x in sstore_pc[p])
            print "met:", p, "=>", restore_ds.get_ds(p, isVyper), "||", pc_str
    elif (event_match_pattern):
        temp_pattern = list(set(event_match_pattern))
        for p in set(event_match_pattern):
            restore_ds.init_reds()
            pc_str = ','.join(str(x) for x in sstore_pc[p])
            print "eve:", p, "=>", restore_ds.get_ds(p, isVyper), "||", pc_str
    elif (no_match_pattern):
        # if (has_transfer or has_transferfrom):
        #     print "[erc721]",
        for p in set(no_match_pattern):
            if 'x' not in p:
                continue
            restore_ds.init_reds()
            pc_str = ','.join(str(x) for x in sstore_pc[p])
            print "noo:", p, "=>", restore_ds.get_ds(p, isVyper), "||", pc_str
    # if len(temp_pattern) > 1:
    #     print "multi pattern!"
    # no_notice_methodids = check_no_notification(temp_pattern, g_path_info)
    # if no_notice_methodids and not is_infinite:
    #     print "no notice:", no_notice_methodids
    # fake_methodids = check_fake_notification(temp_pattern, g_path_info)
    # if fake_methodids and not is_infinite:
    #     print "fake:", fake_methodids


if __name__ == '__main__':
    main(sys.argv[1])
