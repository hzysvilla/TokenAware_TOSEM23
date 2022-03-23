# oyente 源码笔记

## symExec.py

### 全局变量

```python
exec_block  # 整个流程访问过的block个数

visited_edges {  # 每个method中，每条边访问的次数
    methodid: {  # methodid是第一层key
        Edge: visited_count  # Edge作为第二层key， 内容是每条边访问的次数
    }
}

end_ins_dict {
    block: end_ins_pc  # block编号作为key, block的最后一个指令的pc作为value
}

instructions {
    pc: opcode  # pc作为key，opcode字符串形式作为value
}

jump_type {
    block: jump_type  # 每一个区块的跳转类型
}

vertices {
    block: BasicBlock  # block(block开始opcode的pc)作为key，BasicBloc类型的block为value
}

edge {
    block: Edge  # block(编号)作为key，Edge(namedtuple)类型作为value
}
```

### sym_exec_ins()函数

1. global_state 结构

   ```python
   global_state {
        'pc':[] # 存储全局的pc值
        'Ia':{ # storage的值
            'address': # 对应地址的storage值
        }
        'miu_i': # ?
        'value': # CALLVALUE值
        'sender_address':
        'receiver_address':
        'gas_price':
        'origin':
        'currentCoinbase':
        'currentTimeStamp':
        'currentNumber':
        'currentDifficulty':
        'currentGaslimit':
        'balance': {
            'Is':
            'Ia':
        }
        'path_conditions_and_vars': {  # ?
            'path_conditions':
        }
   }
   ```

1. 设置 jump 的地址, `vertices[start].set_jump_target(address)`
   edges[start].append(address)的作用使用？

1. taint_stack 中的元素值保留了是否和参数有关的标识，如果是无关的则直接存储零

1. `SLOAD`逻辑

   1. stack 中 pop 出地址
   1. 判断对应地址是否在 storage 中有值
   1. 有值则取出值
   1. 无值则取零

1. `SSTORE`逻辑

   1. stack 中取出 value 和 address 值
   1. 将 value 存在 storage 对应 addres 中

1. `MSLOAD`只读取某个地址开始的 32 字节

1. `MSTORE`可能存储的位置不存在，以及它前面位置也是不存在的，需要先初始化前面位置为零

1. `AND`8 个 f 是取 methodid

1. Edge 的定义

   ```python
    Edge = namedtuple("Edge", ["v1", "v2"])
   ```

1. BasicBlock 定义

   ```python
    self.start = start_address
    self.end = end_address
    self.instructions = []  # each instruction is a string
    self.jump_target = 0
   ```

1. 以 methodid 为单位，每条边只能访问 LOOP_LIMIT 次

### Stack/Memory/Storage

1. Stack 的存储单元是 32 字节，`PUSH`无论是哪种类型都只存储一个单元

### 存在的输入量

1. CALLDATALOAD

1. CALLER

### 一些字符

1. Is => 和 sender_address 相关

1. Ia => 和 address 所相关，receiver_address

1. Iv => msg.value 相关

## 问题

1. `MSTORE`和`MSTORE8`的区别，这样两种不同大小的数值，改变 Memory 的最小单位为一个字节?

1. 数学类计算操作，如果操作数有无符号，对操作有影响吗？

1. `path_conditions_and_vars`的作用是什么？

1. Memory 的存储单元是多少字节? 32 字节?

1. jump 是存在几条跳转分支的?

   jump 一般分为两种，一种是 jump 上一个 opcode 是 push 一个跳转目的地址，这种 jump 就只有固定的一条分支；还有一种是 jump 上一个 opcode 不是 push，所以跳转的目的地址是不确定的，这种 jump 的跳转分支也就不确定了

1. 为什么没有在 return 这个 opcode 的时候进行分块? 因为 return 处不是块结束处,导致 return 后面的 pop 时栈中已经没有元素了
