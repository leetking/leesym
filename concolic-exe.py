#!/usr/bin/env python3

import sys
import re

from collections import OrderedDict

LEFT = 0
RIGHT = 1

class Instruction:
    def __init__(self, addr_, asm_):
        self.addr = addr_
        self.asm = asm_
        self.loperands = set()
        self.roperands = set()
        self.loffsets = set()
        self.roffsets = set()

    def append_operands(self, offsets, nums):
        self.loffsets.update(offsets[LEFT])
        if len(offsets) == 2:
            self.roffsets.update(offsets[RIGHT])

        self.loperands.add(nums[LEFT])
        if len(nums) == 2:
            self.roperands.add(nums[RIGHT])

    def is_single_operand(self):
        return not self.roperands

    def is_two_operand(self):
        return self.loperands and self.roperands

# 1. (无offset) 立即数，指令中存在 (无offset)
# 2. {}, 没有被污染
# 3. {,,,,} 没有被污染
# 4. {0x0,0x1,0x2,,,,} 被污染
#
# {}, {,,,,}, {0x0, 0x1,,,,}, {0x0,0x1,0x2,0x3,}
# 结论: {} 中 ',' 和指令长度有关
class Operand:
    def __init__(self, offsets, value):
        self._offsets = offsets
        self._value = value

    def is_constant(self):
        pass

# 从小端序表示的hex字符串中获取整数
# 0a000000 => 10
def int_fromhex(s):
    return int.from_bytes(bytes.fromhex(s), "little")

# 记录中的偏移量默认是大端序
# {0x0, 0x1, 0x2,,,}
def parse_offset(off):
    pat = r'{(.*?)}'
    offs = re.findall(pat, off)
    def parse_num(s):
        return [int(x, 16) for x in s.split(',') if x.strip()]
    return [parse_num(off) for off in offs]

def parse_line(line):
    addr, asm, offsets, *nums = line.strip().split('.')
    addr = int(addr, 16)
    offs = parse_offset(offsets)
    nums = [int_fromhex(num) for num in nums if num.strip() ]
    #print(line.strip())
    #print(offs, nums)
    #print("")
    return addr, asm, offs, nums

def parse_trace_file(fname):
    # 记录全部指令，以地址为记录
    instructions = {}
    with open(trace_file, 'r') as tf:
        for line in tf:
            addr, asm, offs, nums = parse_line(line)
            if addr not in instructions:
                instructions[addr] = Instruction(addr, asm)
            ins = instructions[addr]
            ins.append_operands(offs, nums)
    return instructions

def parse(fname):
    instructions = OrderedDict()
    with open(trace_file, 'r') as tf:
        for line in tf:
            line = line.strip()
            addr, *_ = line.split('.')
            if addr not in instructions:
                instructions[addr] = [line]
            else:
                instructions[addr].append(line)
    for addr, ins in instructions.items():
        for i in ins:
            print(i)

# main
trace_file = sys.argv[1]

parse(trace_file)

#instructions = parse_trace_file(trace_file)

#print("ins: ", len(instructions))

#for addr, ins in instructions.items():
#    print(addr, ins.asm, ins.loffsets, ins.roffsets, ins.loperands, ins.roperands)
