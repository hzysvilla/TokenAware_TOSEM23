# -*- coding: utf-8 -*-
exp_dict = {}  # pattern expression => op, params, params_num
visit_order = {}  # 每个可疑变量的访问顺序
is_exp_visited = {}
exp_parent = {}
var_visit_order = []
is_vyper = False


def find_bracket_pos(inputstr):
    left_flag = True
    right_flag = True
    left_pos = 0
    right_pos = 0
    for i in range(len(inputstr)):
        if inputstr[i] == "(" and left_flag:
            left_pos = i
            left_flag = False
        if inputstr[len(inputstr) - 1 - i] == ")" and right_flag:
            right_pos = len(inputstr) - 1 - i
            right_flag = False

    if (not left_flag) and (not right_flag):
        return True, left_pos, right_pos
    else:
        return False, 0, 0


def get_operator_and_operand(inputstr):

    operator = ""
    operands = []
    ok, pos1, pos2 = find_bracket_pos(inputstr)
    if ok:
        operator = inputstr[0:pos1]
        raw_operand = inputstr[pos1 + 1: pos2]

        balances = 0
        op_pos = []
        mul_op = False
        
        for i in range(len(raw_operand)):
            if raw_operand[i] == "(":
                balances += 1
            if raw_operand[i] == ")":
                balances -= 1
            if raw_operand[i] == "," and balances == 0:
                op_pos.append(i)
                mul_op = True
                
        if mul_op:
            for i in range(len(op_pos)):
                if i == 0:
                    operands.append(raw_operand[0:op_pos[i]])
                else:
                    operands.append(raw_operand[op_pos[i-1] + 2:op_pos[i]])
                if i == len(op_pos) - 1:
                    operands.append(raw_operand[op_pos[i] + 2: ])

        else:
            operands.append(raw_operand)
        return True, operator, operands, len(operands)
    else:
        return False, operator, operands, len(operands)


def print_exp(root_str, inputstr, depth):
    global visit_order
    ok, op, opparams, opparamsnum = get_operator_and_operand(inputstr)

    if inputstr not in exp_dict:
        temp = []
        temp.append(op)
        temp.append(opparams)
        temp.append(opparamsnum)
        exp_dict[inputstr] = temp

    # if op == "sha3":
    #     print op
    #     print opparams
    #     print opparamsnum

    if (len(visit_order[root_str]) <= depth):
        visit_order[root_str].append([inputstr])
    else:
        visit_order[root_str][depth].append(inputstr)

    for opparam in opparams:
        # 如果分支是sload开始，则默认为是一个新变量，单独这个变量的访问过程
        if opparam.startswith("sload"):
            if opparam in visit_order:
                continue
            var_visit_order.append(opparam)
            visit_order[opparam] = []
            exp_parent[opparam] = inputstr
            print_exp(opparam, opparam, 0)
            continue
        if "(" in opparam:
            print_exp(root_str, opparam, depth+1)


def restore():
    """restore op to data structure
    """
    structs = {}
    var_to_index = {}
    # for key, value in visit_order.items():
    var_index = 0
    for var in var_visit_order:
        visit = []
        value = visit_order[var]
        for v in value:
            visit = visit + v
        visit_order[var] = visit
        struct = []
        struct_index = 0 
        pre_struct = ""
        for exp in visit:
            re = restore_one_op(exp)
            if (re == ""):
                is_exp_visited[exp] = pre_struct
                continue
            is_exp_visited[exp] = re + str(struct_index)
            pre_struct = is_exp_visited[exp]
            struct.append(re + str(struct_index))
            struct_index = struct_index + 1
        if not struct:
            continue
        # structs.append("->".join(struct[::-1]))
        var_to_index[var] = var_index
        structs[var_index] = struct
        var_index += 1
        # structs.append(struct)
    # 多个变量时关联多个变量之间的引用关系
    for m, p in exp_parent.items():
        # print "m:", m, "p:", p
        if m not in var_to_index:
            continue
        # print visit_order
        for var, order in visit_order.items():
            if var == m or p not in order:
                continue
            if p not in is_exp_visited:
                continue
            p_struct = is_exp_visited[p]
            # print p_struct
            i = var_to_index[var]
            if p_struct not in structs[i]:
                continue
            s = structs[i].index(p_struct)
            structs[i][s] = p_struct + "(" + str(var_to_index[m]) + ")"
    res = {}
    for k, v in structs.items():
        res[k] = "->".join(v[::-1])
    return res


def restore_one_op(expression):
    """restore one op to data structure

    :expression: pattern expression
    :returns: data structure string

    """
    if (expression in is_exp_visited):
        return ""
    # is_exp_visited[expression] = True
    exp_info = exp_dict[expression]
    op = exp_info[0]
    op_params = exp_info[1]
    op_params_num = exp_info[2]

    if (op == "add"):
        sha3_exp = ""
        is_all_symbol = True
        for exp in op_params:
            if exp.isdigit() and int(exp) > 20:
                return ""
            if exp.isdigit():
                is_all_symbol = False
            if exp.startswith("sha3"):
                sha3_exp = exp
                break
        if is_all_symbol and not sha3_exp:
            return ""
        if sha3_exp == "" or exp_dict[sha3_exp][2] == 2:
            # is_exp_visited[expression] = "struct"
            return "struct"
        if exp_dict[sha3_exp][2] == 1:
            if is_vyper:
                is_exp_visited[sha3_exp] = "array/struct"
                return "array/struct"
            else:
                is_exp_visited[sha3_exp] = "array"
                return "array"
        # sha3_struct = restore_one_op(sha3_exp)
        # if sha3_struct == "map":
        #     is_exp_visited[expression] = "map->strcut"
        #     return "map->struct"
        # if sha3_struct == "array":
        #     is_exp_visited[expression] = "array"
        #     return "array"
    if (op == "sha3"):
        if (op_params_num == 1):
            # is_exp_visited[expression] = "array"
            if is_vyper:
                return "array/struct"
            else:
                return "array"
        if (op_params_num == 2):
            # is_exp_visited[expression] = "map"
            return "map"
        # is_exp_visited[expression] = ""
        return ""
    # is_exp_visited[expression] = ""
    return ""


def get_ds(expstr, isVyper):
    global is_vyper
    global var_visit_order
    global visit_order
    var_visit_order.append(expstr)
    visit_order[expstr] = []
    is_vyper = isVyper
    print_exp(expstr, expstr, 0)
    return restore()


def init_reds():
    global exp_dict
    global visit_order
    global is_exp_visited
    global exp_parent
    global var_visit_order
    exp_dict = {}  # pattern expression => op, params, params_num
    visit_order = {}  # 每个可疑变量的访问顺序
    is_exp_visited = {}
    exp_parent = {}
    var_visit_order = []
