import utils  # added by heppen


class Generator:
    def __init__(self):
        self.countstack = 0
        self.countdata = 0
        self.count = 0

    def gen_stack_var(self):
        self.countstack += 1
        return "s" + str(self.countstack)

    def gen_data_var(self):
        self.countdata += 1
        return "Id_" + str(self.countdata)

    def gen_load_data_var(self, position):  # for taint data
        self.countdata += 1
        return "Cload(" + str(position) + ')'

    def gen_data_var(self, position):
        self.countdata += 1
        return "Id_" + str(self.countdata)

    def gen_data_size(self):
        return "Id_size"

    def gen_arbitrary_sha3(self, offset, size):
        return "sha3" + "[" + str(offset) + ":" + str(offset + size) + "]"

    # added by heppen.
    def gen_sha3_var(self, offset, length, memory):
        sha3_name = "sha3("
        if len(memory) == 0 or not utils.isAllReal(offset, length):
            return sha3_name + ')'
        num = length / 32
        for i in range(num):
            if int(offset) + i * 32 not in memory:
                sha3_name = "sha3("
                break
            sha3_name += "#" + str(memory[int(offset) + i * 32])
        return sha3_name + ')'

    # no simplify pattern expression
    def gen_sha3_origin_var(self, offset, length, memory):
        sha3_name = "sha3("
        if len(memory) == 0 or not utils.isAllReal(offset, length):
            return sha3_name + ')'
        num = length / 32
        items = []
        for i in range(num):
            if int(offset) + i*32 not in memory:
                items = []
                break
            items.append(str(memory[int(offset) + i*32]))
        return sha3_name + ', '.join(items) + ')'

    def gen_copy_data_var(self, address):  # for taint data
        return "mem_Copy_(" + str(address) + ')'

    def gen_mem_var(self, address):
        return "mem_(" + str(address) + ')'

    def gen_arbitrary_var(self):
        self.count += 1
        return "some_var_" + str(self.count)

    def gen_arbitrary_address_var(self):
        self.count += 1
        return "some_address_" + str(self.count)

    def gen_owner_store_var(self, position):
        return "sload(" + str(position) + ")"

    def gen_gas_var(self):
        self.count += 1
        return "gas_" + str(self.count)

    def gen_gas_price_var(self):
        return "Ip"

    def gen_address_var(self):
        return "Ia"

    def gen_caller_var(self):
        return "Is"

    def gen_origin_var(self):
        return "Io"

    def gen_balance_var(self):
        self.count += 1
        return "balance_" + str(self.count)

    def gen_code_var(self, address, position, bytecount):
        return "code_" + str(address) + "_" + str(position) + "_" + str(
            bytecount)

    def gen_code_size_var(self, address):
        return "code_size_" + str(address)
