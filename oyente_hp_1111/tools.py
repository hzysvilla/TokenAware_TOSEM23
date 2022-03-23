# -*- coding: utf-8 -*_
import pprint  # for debug
import re
# import ipdb

from utils import *
# from symExec import TRANSFER_METHOD_ID
# from symExec import TRANSFERFROM_METHOD_ID


def check_no_notification(pattern, path_info):
    """检测非erc20标准函数中是否有路径中修改了M，但是没有提交事件

    """
    if not pattern:
        return []
    no_notice_methodids = []
    for path, info in path_info.items():
        methodid = info.get_methodid()
        is_end = info.get_is_end()
        if (methodid == "0xa9059cbb" or
                methodid == "0x23b872dd" or not is_end):
            continue
        gt = info.get_gt()
        lt = info.get_lt()
        is_zero = info.get_is_zero()
        eq = info.get_eq()
        jumpi_flags = info.get_jumpi_flag()
        sstore = info.get_sstore()
        event = info.get_event()
        has_call = info.get_has_call()
        addrs = info.get_addrs()
        is_write = False
        for key in sstore:
            for addr in addrs:
                temp_key = key.replace(addr, 'x')
                # if methodid == "0x42966c68": # debug
                #     print addr, temp_key
                if temp_key in pattern:
                    is_write = True
                    break
            if is_write:
                break
        if is_write and not event:
            no_notice_methodids.append(methodid)
        # if methodid == "0x42966c68":  # debug
        #     print "enter:", sstore

    return set(no_notice_methodids)


def check_fake_notification(pattern, path_info):
    """检测整个符号执行过程中是否有路径中存在fake notification漏洞

    :pattern: 已经识别出来的pattern表达式
    :path_info: 每一条路径的相关信息
    :returns: 存在Fake Notification漏洞的函数id

    """
    if not pattern:
        return []
    fake_methodids = []
    for path, info in path_info.items():
        methodid = info.get_methodid()
        gt = info.get_gt()
        lt = info.get_lt()
        is_zero = info.get_is_zero()
        eq = info.get_eq()
        jumpi_flags = info.get_jumpi_flag()
        sstore = info.get_sstore()
        event = info.get_event()
        has_call = info.get_has_call()
        addrs = info.get_addrs()
        # if methodid == "0xc18b4136" and event:
        #     print methodid, sstore, event  # debug
        #     print "gt:", gt
        #     print "lt:", lt
        #     print "is_zero:", is_zero
        #     print "eq:", eq
        #     print "jumpi_flags:", jumpi_flags
        #     print "has_call:", has_call
        #     print "addrs:", addrs
        #     print "#####################"

        # 函数中一条路径存在即可，不对其他同函数内的路径进行判断
        if methodid in fake_methodids:
            continue

        # 以下情况下不是Fake Notification:
        # 1. 没有event信息
        # 2. event信息收集出错没有三个参数
        # 3. 路径中有跨合约调用
        # 4. 路径有value > 0 或者 value < 0 或者 value == 0
        # 5. 路径中有from==to的判断
        if (not event or len(event) < 3 or has_call):
            continue
        # 可能存在多个event
        is_no_fake = False
        for i in range(0, len(event), 3):
            # from == to
            if (event[i] in eq and event[i+1] in eq):
                is_no_fake = True
                break
            # value == 0
            if (event[i+2] == 0 or event[i+2] == '0' or event[i+2] in lt
                    or event[i+2] in eq or event[i+2] in is_zero
                    or event[i+2] in jumpi_flags or event[i+2] in gt):
                is_no_fake = True
                break
        if is_no_fake:
            continue

        # 判断是否有修改过M
        is_write = False
        for key in sstore:
            # from和to是0的话不进行表达式的替换，因为0可能出现在表达式的很多地方
            # 可能有多个event，只要其中一个event对应了M的修改即可
            for i in range(0, len(event), 3):
                temp_key = key
                # print "temp_key:", temp_key, i  # debug
                if len(event[i]) > 1:
                    temp_key = key.replace(event[i], 'x')
                if len(event[i+1]) > 1:
                    temp_key = temp_key.replace(event[i+1], 'x')
                # 修改了M
                # print "after temp_key:", temp_key, i  # debug
                if temp_key in pattern:
                    is_write = True
                    break
            if is_write:
                break
            # 如果修改的地址不能和event里的地址对应上，则修改表达式中addr变量的为x
            out_temp_key = modify_sstore_addr(key, addrs)
            if out_temp_key in pattern:
                is_write = True
                break
            # print "temp_key:", out_temp_key  # debug
        if not is_write:
            fake_methodids.append(methodid)
            # print "is fake!!!" # debug
            # print "================"
    return fake_methodids


def check_fake_notice(params):
    """检查是否有fake notification漏洞

    :params: 一条路径上的一些数据记录
    :returns: True表示存在漏洞，False表示不存在漏洞

    """
    sstore_info = params.sstore_info_in_path
    event_info = params.event_info_in_path
    lt_info = params.lt_in_path
    gt_info = params.gt_in_path
    eq_info = params.eq_in_path
    has_call = params.has_call_in_path
    iszero_info = params.iszero_in_path
    jumpi_flags = params.jumpi_flags_in_path
    if sstore_info or not event_info:
        return False
    if len(event_info) < 3:
        return False
    if has_call:
        return False
    if event_info[2] == 0 or event_info[2] == '0':
        return False
    # 判断value是否为零
    if event_info[2] in lt_info or event_info[2] in gt_info or event_info[2] in eq_info:
        return False
    if event_info[2] in iszero_info:
        return False
    # solidity 0.5.0以后判断零直接让变量作为jumpi的跳转条件
    if event_info[2] in jumpi_flags:
        return False
    # 判断from和to地址是否相等
    if event_info[0] in eq_info and event_info[1] in eq_info:
        return False
    return True


def compact_string(s):
    """去除多余的换行符、tab和多个空白符，使字符串更加紧凑
    :returns: 紧凑后的字符串

    """
    return " ".join(s.split())


def solidity_methodid_process(instr_parts, methodiddata):
    """solidity合约执行每个instruction前判断是否处在进入函数前比较函数id的过程

    :instr_part: 当前instruction的每个指令和操作数
    :methodiddata: 当前函数的一些信息

    """
    lock_now = methodiddata.get('lock')
    if not lock_now:
        step_now = methodiddata.get('step')
        if instr_parts[0].startswith('PUSH4'):
            if step_now == 0:
                pushed_value = instr_parts[1]
                methodiddata['methodid'] = pushed_value
                methodiddata['step'] = 1
            else:
                methodiddata['step'] = 0
        elif instr_parts[0].startswith('DUP'):
            if step_now == 1:
                pass
            else:
                methodiddata['step'] = 0
        elif instr_parts[0] == 'EQ':
            if step_now == 1:
                methodiddata['step'] = 2
            else:
                methodiddata['step'] = 0
        elif instr_parts[0].startswith('PUSH'):
            if step_now == 2:
                methodiddata['step'] = 3
            else:
                methodiddata['step'] = 0
        elif instr_parts[0] == 'JUMPI':
            if step_now == 3:
                methodiddata['step'] = 4
            else:
                methodiddata['step'] = 0
        else:
            methodiddata['step'] = 0


def vyper_methodid_process(instr_parts, methodiddata):
    """vyper合约执行每个instruction前判断是否处在进入函数前比较函数id的过程

    :instr_part: 当前instruction的每个指令和操作数
    :methodiddata: 当前函数的一些信息

    """
    lock_now = methodiddata.get('lock')
    if not lock_now:
        # print instr_parts
        step_now = methodiddata.get('step')
        if instr_parts[0].startswith('PUSH4', 0):
            pushed_value = instr_parts[1]
            if step_now == 0:
                methodiddata['methodid'] = pushed_value
                methodiddata['step'] = step_now + 1
        elif instr_parts[0].startswith('PUSH1', 0):
            if step_now == 1:
                methodiddata['step'] = step_now + 1
            else:
                methodiddata['step'] = 0
        elif instr_parts[0] == "MLOAD":
            if step_now == 2:
                methodiddata['step'] = step_now + 1
            else:
                methodiddata['step'] = 0
        elif instr_parts[0] == "EQ":
            if step_now == 3:
                methodiddata['step'] = step_now + 1
            else:
                methodiddata['step'] = 0
        elif instr_parts[0] == "ISZERO":
            if step_now == 4:
                methodiddata['step'] = step_now + 1
            else:
                methodiddata['step'] = 0
        elif instr_parts[0] == "JUMPI":
            if step_now == 6:
                methodiddata['step'] = step_now + 1
            else:
                methodiddata['step'] = 0
        elif instr_parts[0].startswith('PUSH', 0):
            if step_now == 5:
                methodiddata['step'] = step_now + 1
            else:
                methodiddata['step'] = 0
        else:
            methodiddata['step'] = 0


def check_fake_deposit(sstore_info_in_path, pattern, addrs):
    """检查是否是fake deposit漏洞

    :sstore_info_in_path: TODO
    :pattern: TODO
    :returns: TODO

    """
    for path, keys in sstore_info_in_path.items():
        # if (len(keys) < 2):
        #     return False
        for k in keys:
            mod = modify_sstore_addr(k, addrs)
            if mod in pattern:
                return True
    return False


def compare_method_map_transfer(sstore_info, addrs):
    """solidity下比较transfer函数与map

    :sstore_info: TODO
    :returns: TODO

    """
    pattern = ""
    from_patterns = []
    to_patterns = []
    patterns = []
    for key, values in sstore_info.items():
        for value in values:
            if ("Is" in key) and ("Cload(36)" in value):
                if value.startswith("sub") or ("sub" in value):
                    from_pattern = modify_sstore_addr(key, addrs)
                    from_patterns.append(from_pattern)
            if ("Cload(4)" in key) and ("Cload(36)" in value):
                if value.startswith("add") or ("add" in value):
                    to_pattern = modify_sstore_addr(key, addrs)
                    to_patterns.append(to_pattern)
    for p in from_patterns:
        if p in to_patterns:
            patterns.append(p)
    return patterns


def compare_method_map_transferfrom(sstore_info, addrs):
    """比较transferfrom函数与map

    :sstore_info: TODO
    :returns: TODO

    """
    from_patterns = []
    to_patterns = []
    patterns = []
    # print "sstore_info", sstore_info
    for key, values in sstore_info.items():
        for value in values:
            if ("Cload(4)" in key) and ("Cload(68)" in value):
                if value.startswith("sub") or ("sub" in value):
                    from_pattern = modify_sstore_addr(key, addrs)
                    from_patterns.append(from_pattern)
            if ("Cload(36)" in key) and ("Cload(68)" in value):
                if value.startswith("add") or ("add" in value):
                    to_pattern = modify_sstore_addr(key, addrs)
                    to_patterns.append(to_pattern)
    for p in from_patterns:
        if p in to_patterns:
            patterns.append(p)
    return patterns


def erc1155_compare_method_map(sstore_info, addrs):
    from_patterns = []
    to_patterns = []
    patterns = []
    for key, values in sstore_info.items():
        for value in values:
            # print "ercc1155 value:", value
            if ("Cload(4)" in key or "msg(4)" in key) and ("Cload(100)" in value or "msg(100)" in value):
                if value.startswith("sub") or ("sub" in value):
                    from_pattern = modify_sstore_addr(key, addrs)
                    from_patterns.append(from_pattern)
            if ("Cload(36)" in key or "msg(36)" in key) and ("Cload(100)" in value or "msg(100)" in value):
                if value.startswith("add") or ("add" in value):
                    to_pattern = modify_sstore_addr(key, addrs)
                    to_patterns.append(to_pattern)
    for p in from_patterns:
        if p in to_patterns:
            patterns.append(p)
    return patterns



def compare_event_map(event_params, sstore_info, addrs):
    """比较map和event

    :event_params: 标准event中的三个参数from/to/value
    :sstore_info: sstore的key-value对
    :addrs: 所有的地址变量
    :returns: 匹配上的表达式 

    """
    if (len(event_params) < 3):
        return []
    from_patterns = []
    to_patterns = []
    patterns = []
    for key, values in sstore_info.items():
        for value in values:
            if (event_params[0] in key) and (event_params[2] in value):
                if (value.startswith("sub") or ("sub" in value)):
                    # from_pattern = modify_sstore_addr(key, event_params[0])
                    from_pattern = key.replace(event_params[0], "x")
                    from_patterns.append(from_pattern)
            if (event_params[1] in key) and (event_params[2] in value):
                if (value.startswith("add") or ("add" in value)):
                    # to_pattern = modify_sstore_addr(key, addrs)
                    to_pattern = key.replace(event_params[1], "x")
                    to_patterns.append(to_pattern)
    for p in from_patterns:
        if p in to_patterns:
            patterns.append(p)

    return patterns


def erc1155_compare_event_map(event_params, sstore_info, addrs):
    """TODO: Docstring for erc1155_compare_event_map.

    :event_params: TODO
    :sstore_in: TODO
    :returns: TODO

    """
    if (len(event_params) < 5):
        return []
    from_patterns = []
    to_patterns = []
    patterns = []
    for key, values in sstore_info.items():
        for value in values:
            if (event_params[1] in key) and (event_params[3] in value) and (event_params[4] in value):
                if (value.startswith("sub") or ("sub" in value)):
                    from_pattern = modify_sstore_addr(key, addrs)
                    from_patterns.append(from_pattern)
            if (event_params[2] in key) and (event_params[3] in value) and (event_params[4] in value):
                if (value.startswith("add") or ("add" in value)):
                    to_pattern = modify_sstore_addr(key, addrs)
                    to_patterns.append(to_pattern)
    for p in from_patterns:
        if p in to_patterns:
            patterns.append(p)

    return patterns


def no_match_compare(sstore_info, addrs):
    """没有函数和事件的情况下，找出现两次的表达式

    :sstore_info: TODO
    :returns: TODO

    """
    patterns = []
    counter = {}
    for key, values in sstore_info.items():
        for value in values:
            if (not value.startswith("sub") and not value.startswith("add")):
            # if ("sub" not in value and "add" not in value):
                continue
            temp_addr = modify_sstore_addr(key, addrs)
            if temp_addr not in counter:
                counter[temp_addr] = 1
                break;
            else:
                counter[temp_addr] += 1
            if counter[temp_addr] == 2:
                patterns.append(temp_addr)
    return patterns


def vyper_compare_method_map_transfer(sstore_info, addrs):
    """vyper下比较transfer函数与map

    :sstore_info: TODO
    :returns: TODO

    """
    from_patterns = []
    to_patterns = []
    patterns = []
    for key, values in sstore_info.items():
        for value in values:
            if ("Is" in key) and ("Cload(36)" in value or "msg(36)" in value):
                if (value.startswith("sub") or ("sub" in value) or ("add" in value and "not(0)" in value)):
                    from_pattern = key.replace("Is", "x")
                    from_patterns.append(from_pattern)
            if ("Cload(4)" in key or "msg(4)" in key) and ("Cload(36)" in value or "msg(36)" in value):
                if (value.startswith("add") or ("add" in value)):
                    if ("Cload(4)" in key):
                        to_pattern = key.replace("Cload(4)")
                        to_patterns.append(to_pattern)
                    elif("msg(4)" in key):
                        to_pattern = key.replace("msg(4)")
                        to_patterns.append(to_pattern)

    for p in from_patterns:
        if p in to_patterns:
            patterns.append(p)
    return patterns


def vyper_compare_method_map_transferfrom(sstore_info, addrs):
    """比较transferfrom函数与map

    :sstore_info: TODO
    :returns: TODO

    """
    from_patterns = []
    to_patterns = []
    patterns = []
    for key, values in sstore_info.items():
        for value in values:
            if ("Cload(4)" in key or "msg(4)" in key) and ("Cload(68)" in value or "msg(68)" in value):
                # TODO: 也可能是add(not(0))
                if value.startswith("sub") or ("sub" in value) or ("add" in value and "not(0)" in value):
                    if "Cload(4)" in key:
                        from_pattern = key.replace("Cload(4)", "x")
                    elif "msg(4)" in key:
                        from_pattern = key.replace("msg(4)", "x")
                    # from_pattern = modify_sstore_addr(key, addrs)
                    from_patterns.append(from_pattern)
            if ("Cload(36)" in key or "msg(36)" in key) and ("Cload(68)" in value or "msg(68)" in value):
                if value.startswith("add") or ("add" in value):
                    # to_pattern = modify_sstore_addr(key, addrs)
                    if "Cload(36)" in key:
                        to_pattern = key.replace("Cload(36)", "x")
                    elif "msg(36)" in key:
                        to_pattern = key.replace("msg(36)", "x")

                    to_patterns.append(to_pattern)

    for p in from_patterns:
        if p in to_patterns:
            patterns.append(p)
    return patterns


def modify_sstore_addr(sstore_addr, addrs):
    """ 将表达式中和地址相关的变量改成x

    :sstore_addr: 表达式
    :addrs: 所有的地址变量
    :returns: 修改后的表达式
    """
    if isReal(sstore_addr):
        return sstore_addr
    modified_addr = sstore_addr
    for addr in addrs:
        if len(addr) < 2:
            continue
        if addr in sstore_addr:
            modified_addr = modified_addr.replace(addr, 'x')
    return modified_addr

# 获取两个操作数的数学计算opcode的op序列结果
def get_computed_two_operand(first, second, length):
    if first or second:
        return first + second + [length]
    return []


def get_address_from_pattern(patterns, sha3_data, sha3_hash):
    address = ""
    sstore_loc = sha3_hash
    for pattern in patterns:
        # pattern1
        if re.match(r"sha3\(#x#\d+\)", pattern):
            pattern_index = int(pattern[:-1].split('#'))[-1]  # digit in sha3.
            data_half_len = int(len(sha3_data) / 2)
            data_index = int(sha3_data[data_half_len:])
            if pattern_index == data_index:
                address = sha3_data[:data_half_len]
                break

        elif re.match(r"(\d+) \+ sha3\(#x#(\d+)\)", pattern):
            match = re.match(r"(\d+) \+ sha3\(#x#(\d+)\)", pattern)
            pattern_index = int(match.group(2))  # digit in sha3.
            pattern_offset = int(match.group(1))  # digit out of sha3.
            data_half_len = int(len(sha3_data) / 2)
            data_index = int(sha3_data[data_half_len:])
            if pattern_index == data_index:
                address = sha3_data[:data_half_len]
                sstore_loc = hex(int(sstore_loc, 16) + pattern_offset)
                break

    return address, sstore_loc


def process_mint(transfer_event, transfer_sstore):
    if (not transfer_event) or (not transfer_sstore):
        return None
    for str_event in transfer_event:
        str_from = str_event.split('&')[1]
        str_to = str_event.split('&')[3]
        str_value = str_event.split('&')[5]
        if str_from == "0":
            for str_sstore in transfer_sstore:
                str_sstore_value = str_sstore.split('&')[-1]
                if str_to in str_sstore_value and (' + ' +
                                                   str_value) in str_sstore:
                    return [str_sstore.split('&')[1].replace(str_to, 'x')]
        return None


def checkpoint_process_mint(transfer_event, transfer_sstore):
    if (not transfer_event) or (not transfer_sstore):
        return None
    for str_event in transfer_event:
        str_from = str_event.split('&')[1]
        str_to = str_event.split('&')[3]
        str_value = str_event.split('&')[5]
        if str_from == "0":
            for str_sstore in transfer_sstore:
                str_sstore_value = str_sstore.split('&')[-1]
                if str_to in str_sstore_value \
                        and ('+\n       Extract(127, 0, Cload(36)))' in str_sstore_value
                             or 'Extract(127, 0, Cload(36)) +' in str_sstore_value):
                    return [str_sstore.split('&')[1].replace(str_to, 'x')]
        return None


# capture balance address from the method which has Transfer event.
def process_tra(transfer_event, transfer_sstore):
    if (not transfer_event) or (not transfer_sstore):
        return None
    pattern = []
    for str_event in transfer_event:
        str_from = str_event.split('&')[1]
        str_to = str_event.split('&')[3]
        str_value = str_event.split('&')[5]
        add_addr_list = []
        sub_addr_list = []
        for str_sstore in transfer_sstore:
            str_sstore_value = str_sstore.split('&')[-1]
            if str_from in str_sstore_value and (
                    ' - ' + str_value) in str_sstore_value:
                sub_addr = str_sstore.split('&')[1].replace(str_from, 'x')
                sub_addr_list.append(sub_addr)
            elif str_to in str_sstore_value and (
                    ' + ' + str_value) in str_sstore_value:
                add_addr = str_sstore.split('&')[1].replace(str_to, 'x')
                add_addr_list.append(add_addr)
        for addr in add_addr_list:
            if addr in sub_addr_list:
                pattern.append(addr)
    if pattern:
        return list(set(pattern))
    return None


# capture balance address from the method which has Transfer event, and balance is checkpoint type
def checkpoint_process_tra(transfer_event, transfer_sstore):
    if (not transfer_event) or (not transfer_sstore):
        return None
    pattern = []
    for str_event in transfer_event:
        str_from = str_event.split('&')[1]
        str_to = str_event.split('&')[3]
        str_value = str_event.split('&')[5]
        add_addr_list = []
        sub_addr_list = []
        for str_sstore in transfer_sstore:
            str_sstore_value = str_sstore.split('&')[-1]
            if str_from in str_sstore_value \
                    and '340282366920938463463374607431768211455*\n       Extract(127, 0, Cload(36))' in str_sstore_value:
                sub_addr = str_sstore.split('&')[1].replace(str_from, 'x')
                sub_addr_list.append(sub_addr)
            elif str_to in str_sstore_value \
                    and ('+\n       Extract(127, 0, Cload(36)))' in str_sstore_value
                         or 'Extract(127, 0, Cload(36)) +' in str_sstore_value):
                add_addr = str_sstore.split('&')[1].replace(str_to, 'x')
                add_addr_list.append(add_addr)
        for addr in add_addr_list:
            if addr in sub_addr_list:
                pattern.append(addr.replace('\n', ' '))
    if pattern:
        return list(set(pattern))
    return None


# capture balance address from sstore addresses and values in transfer method
def process_transfer(transfer):
    if not transfer:
        return 'empty'
    pattern = []
    sub_addr_list = []
    add_addr_list = []
    for addr in transfer:
        for value in transfer[addr]:
            sub_value = re.findall(r"-[\s\S]*Cload\(36\)", value)
            add1_value = re.findall(r"Cload\(36\)[\s\S]*\+", value)
            add2_value = re.findall(r"\+[\s\S]*Cload\(36\)", value)
            if sub_value or add1_value or add2_value:
                break
        if sub_value:
            sub_addr = addr.replace("Is", "x")
            sub_addr_list.append(sub_addr)
        elif add1_value or add2_value:
            add_addr = addr.replace("Cload(4)", "x")
            add_addr_list.append(add_addr)

    for addr in sub_addr_list:
        if addr in add_addr_list:
            pattern.append(addr)
    if pattern:
        return pattern
    return None


# capture balance address from sstore addresses and values in transfer method when balance is checkpoint type.


def checkpoint_process_transfer(transfer):
    if not transfer:
        return 'empty'
    pattern = []
    sub_addr_list = []
    add_addr_list = []
    # pprint.pprint(transfer)
    for addr in transfer:  # addr is stored address, one address may store many values.
        # print addr   # debug
        for value in transfer[addr]:
            # print "\naddr => ", addr, "\nvalue => ", value  # debug
            sub_value = re.findall(
                r"340282366920938463463374607431768211455\*\n\s*Extract\(127, 0, Cload\(36\)\)",
                value)
            add_value_1 = re.findall(r"Extract\(127, 0, Cload\(36\)\) \+",
                                     value)
            add_value_2 = re.findall(r"\+\n\s*Extract\(127, 0, Cload\(36\)\)",
                                     value)
            if sub_value or add_value_1 or add_value_2:
                break
        if sub_value:
            sub_addr = addr.replace("Is", "x")
            sub_addr_list.append(sub_addr)
        elif add_value_1 or add_value_2:
            add_addr = addr.replace("Cload(4)", "x")
            add_addr_list.append(add_addr)

    for addr in sub_addr_list:
        if addr in add_addr_list:
            pattern.append(addr.replace('\n', ' '))
    if pattern:
        return pattern
    return None


# capture balance address from sstore addresses and values in transferFrom method
def process_transferfrom(transferfrom):
    if not transferfrom:
        return 'empty'
    pattern = []
    sub_addr_list = []
    add_addr_list = []
    for addr in transferfrom:
        for value in transferfrom[addr]:
            sub_value = re.findall(r"-[\s\S]*Cload\(68\)", value)
            add1_value = re.findall(r"Cload\(68\)[\s\S]*\+", value)
            add2_value = re.findall(r"\+[\s\S]*Cload\(68\)", value)
            if sub_value or add1_value or add2_value:
                break
        if sub_value:
            sub_addr = addr.replace("Cload(4)", "x")
            sub_addr_list.append(sub_addr)
        elif add1_value or add2_value:
            add_addr = addr.replace("Cload(36)", "x")
            add_addr_list.append(add_addr)

    for addr in sub_addr_list:
        if addr in add_addr_list:
            pattern.append(addr)
    if pattern:
        return pattern
    return None


# capture balance address from sstore addresses and values in transferFrom method when balance is checkpoint type.


def checkpoint_process_transferfrom(transferfrom):
    if not transferfrom:
        return 'empty'
    pattern = []
    sub_addr_list = []
    add_addr_list = []
    for addr in transferfrom:
        for value in transferfrom[addr]:
            sub_value = re.findall(
                r"340282366920938463463374607431768211455\*\n\s*Extract\(127, 0, Cload\(68\)\)",
                value)
            add_value_1 = re.findall(r"Extract\(127, 0, Cload\(68\)\) \+",
                                     value)
            add_value_2 = re.findall(r"\+\n\s*Extract\(127, 0, Cload\(68\)\)",
                                     value)
            if sub_value or add_value_1 or add_value_2:
                break
        if sub_value:
            sub_addr = addr.replace("Cload(4)", "x")
            sub_addr_list.append(sub_addr)
        elif add_value_1 or add_value_2:
            add_addr = addr.replace("Cload(36)", "x")
            add_addr_list.append(add_addr)

    for addr in sub_addr_list:
        if addr in add_addr_list:
            pattern.append(addr.replace('\n', ' '))
    if pattern:
        return pattern
    return None


# get kua type possible pattern
def get_possible_pattern(sstore):
    if not sstore:
        return False
    pattern = []
    sub_addr_list = []
    add_addr_list = []
    sub_value = ""
    add_value_1 = ""
    add_value_2 = ""
    # in the same method, from address sub value, to address add value.
    for methodid in sstore:
        for addr in sstore[methodid]:
            # pattern address need start with sha3 and Cload([digits]) in it.
            if re.match(r"^sha3\(#Cload\(\d+\).*#\d+.*$", addr):
                for value in sstore[methodid][addr]:
                    if "sload(" + addr + ")" in value:
                        sub_value = re.findall(r"\- Cload\(\d+\)", value)
                        add_value_1 = re.findall(r"\+ Cload\(\d+\)", value)
                        add_value_2 = re.findall(r"Cload\(d+\) \+", value)
                        if sub_value or add_value_1 or add_value_2:
                            break
                if sub_value:
                    sub_addr_list.append(re.sub(r'Cload\(\d+\)', 'x', addr))
                if add_value_1 or add_value_2:
                    add_addr_list.append(re.sub(r'Cload\(\d+\)', 'x', addr))
    # print "sub_addr:", sub_addr_list  # debug
    # print "add_addr:", add_addr_list  # debug

        for addr in sub_addr_list:
            if addr in add_addr_list and addr not in pattern:
                pattern.append(addr)
    if pattern:
        return pattern
    return False


def get_etoken_possible_pattern(sstore):
    if not sstore:
        return False
    pattern = []
    sub_addr_list = []
    add_addr_list = []
    sub_value = ""
    add_value_1 = ""
    add_value_2 = ""
    for methodid in sstore:
        for addr in sstore[methodid]:
            # pattern address need start with sha3 and Cload([digits]) in it.
            if re.match(r"^sha3\(#.*\)#\d+ \+ sha3\(#.*#\d+\)\)$", addr):
                for value in sstore[methodid][addr]:
                    if "sload(" + addr + ")" in value:
                        sub_value = re.findall(r"\-(\n|\s)Cload\(\d+\)", value)
                        add_value_1 = re.findall(r"\+(\n|\s)Cload\(\d+\)",
                                                 value)
                        add_value_2 = re.findall(r"Cload\(d+\)(\n|\s)\+",
                                                 value)
                        if sub_value or add_value_1 or add_value_2:
                            break
                if sub_value:
                    sub_addr_list.append(
                        re.sub(r'(Cload\(\d+\)|Is)', 'x', addr))
                if add_value_1 or add_value_2:
                    add_addr_list.append(
                        re.sub(r'(Cload\(\d+\)|Is)', 'x', addr))
    # print "sub_addr:", sub_addr_list  # debug
    # print "add_addr:", add_addr_list  # debug

        for addr in sub_addr_list:
            # if addr in add_addr_list:
            # print "methodid:", methodid
            if addr in add_addr_list and addr not in pattern:
                pattern.append(addr)
    if pattern:
        return pattern
    return False
