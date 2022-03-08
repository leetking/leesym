#!/usr/bin/env python3

import sys
import re
import itertools
import functools
import operator
import z3
from collections import OrderedDict
from bisect import bisect_left


NONE_OFFSET = -1
NONE_ORDER  = -1

def int_fromhex(s: str) -> int:
    """从小端序表示的 hex 字符串中获取整数
    0a000000 => 10
    """
    return int.from_bytes(bytes.fromhex(s), "little")

def get_byte(num, idx):
    return (num >> (8*idx)) & 0xff

class Instruction:
    @staticmethod
    def _is_condjmp(asm):
        ins = asm.split()[0]
        if 'j' != ins[0]:
            return False
        # js: jump if SF set
        if ins in ('jz',   'jnz',  'jl',  'jnl',
                   'jbe',  'jnbe', 'jle', 'jnle',
                   'ja',   'jna',  'js',
                   'jb', 'jnb'):
            return True
        print("WARN: maybe forget condition jump: ", asm)
        return False

    @staticmethod
    def _is_jmp(asm):
        return 'jmp' == asm.split()[0]

    @staticmethod
    def _classify(addr, asm, size=None, result=None, offsets=None, values=None):
        ins = asm.split()[0]
        if ins in ('cmp', 'test'):
            return CompareIns(addr, asm, size, offsets, values)
        if ins in ('jmp'):
            return JumpIns(addr, asm, size, result, offsets, values)
        if Instruction._is_condjmp(ins):
            return CondJumpIns(addr, asm)
        if ins in ('add', 'sub', 'mul', 'imul', 'div', 'not', 'and', 'or', 'xor', 'shr', 'shl', 'lea'):
            return ArithmeticIns(addr, asm, size, offsets, values)
        raise ValueError("Unspoort instruction {}".format(asm))

    @staticmethod
    def from_trace(trace: str):
        def parse_offsets(offs: str):
            def parse_offset(s: str):
                return tuple(map(lambda x: int(x, 16) if x else NONE_OFFSET, s.split(',')))[:-1]
            pat = r'{(.*?)}'
            offs = re.findall(pat, offs)
            return tuple(parse_offset(off) for off in offs)
        addr, asm, *rest = trace.strip().split('.')
        addr = int(addr, 16)
        asm = asm.lower()
        result = None
        if Instruction._is_condjmp(asm):
            return Instruction._classify(addr, asm)
        if Instruction._is_jmp(asm):
            result, offsets, *values = rest
        else:
            offsets, *values = rest
        offsets = parse_offsets(offsets)
        values = tuple(int_fromhex(v) for v in values if v)
        size = max(len(off) for off in offsets)
        return Instruction._classify(addr, asm, size, result, offsets, values)


class ArithmeticIns:
    def __init__(self, addr, asm, size, offsets, values):
        self.addr = addr
        self.asm = asm
        self.size = size
        self.offsets = offsets
        self.values = values
        self._result = None

    def execute(self):
        if self._result:
            return self._result
        ins = self.asm.split()[0]
        values = self.values
        op = {
            'add': operator.add,
            'sub': operator.sub,
            'mul': operator.mul,
            'imul': operator.mul,
            'div': operator.floordiv,
            #'not': operator.not_,      # 按bits操作
            'and': operator.and_,
            'or': operator.or_,
            'xor': operator.xor,
            'shr': operator.irshift,     # 逻辑移位
            'shl': operator.lshift,
            #'lea': _,
        }
        if ins == 'not':
            assert 1 == len(values)
            result = ~values[0]
        elif ins in ('add', 'sub', 'mul', 'imul', 'div',
                     'and', 'or', 'xor', 'shr', 'shl'):
            assert 2 == len(values)
            result = op[ins](values[0], values[1])
        elif ins == 'lea':
            assert 4 == len(values)
            result = values[0] + values[1] * values[2] + values[3]
        else:
            raise ValueError("Unspoort instruction {}".format(self.asm))
        # fixed size
        self._result = result & ((1<<(8*self.size))-1)
        return self._result

    def symbolize(self):
        pass


def is_arimetic(ins):
    return isinstance(ins, ArithmeticIns)


def is_leains(ins):
    return ins.asm.startswith('lea')


COND_UNSPPORT = 0  # Unspport now, e.g. js
COND_EQUAL = 0x1   # ==
COND_NOEQ  = 0x2   # !=
COND_LESS  = 0x3   # <
COND_LEEQ  = 0x4   # <=
COND_GREAT = 0x5   # >
COND_GREATEQ = 0x6 # >=

class CondJumpIns:
    def __init__(self, addr, asm):
        self.addr = addr
        self.asm = asm

    @property
    def condition(self):
        ins = self.asm.split()[0]
        if ins == 'jz':
            return COND_EQUAL
        if ins == 'jnz':
            return COND_NOEQ
        if ins in ('jl', 'jb'):
            return COND_LESS
        if ins in ('jle', 'jbe'):
            return COND_LEEQ
        if ins in ('ja', 'jnle', 'jnbe'):
            return COND_GREAT
        if ins in ('jnl', 'jnb'):
            return COND_GREATEQ
        if ins in ('js'):
            print("WARN: Ignore condition jump: ", ins)
            return COND_UNSPPORT
        else:
            raise ValueError("Unspport instruction {}".format(ins))

    def execute(self):
        raise ValueError("Condition Jump Instruction can't execute")

    def symbolize(self):
        raise ValueError("Condition Jump Instruction can't symbolize")


def is_condjmp(ins):
    return isinstance(ins, CondJumpIns)


class CompareIns:
    def __init__(self, addr, asm, size, offsets, values):
        self.addr = addr
        self.asm = asm
        self.size = size
        self.offsets = offsets
        self.values = values
        self.condition = None

    def execute(self):
        raise ValueError("Compare Instruction can't execute")

    def symbolize(self):
        assert self.condition


def is_compare(ins):
    return isinstance(ins, CompareIns)


class JumpIns:
    def __init__(self, addr, asm, size, result, offsets, values):
        self.addr = addr
        self.asm = asm
        self.size = size
        self.result = result
        self.offsets = offsets
        self.values = values

    def execute(self):
        raise ValueError("Jump Instruction can't execute")

    def symbolize(self):
        pass


def parse_trace_file(fname):
    # 记录全部指令，以地址为记录
    instructions = []
    with open(trace_file, 'r') as tf:
        for trace in tf:
            ins = Instruction.from_trace(trace)
            # discard condtion jump
            if is_condjmp(ins):
                if not instructions or not is_compare(instructions[-1]):
                    print("WARN: single condtion jump. (0x{:x}: {})".format(ins.addr, ins.asm))
                elif COND_UNSPPORT == ins.condition:
                    del instructions[-1]
                else:
                    instructions[-1].condition = ins.condition
            else:
                instructions.append(ins)
    return instructions


def previous_instruction(instructions, idx, value, sameoffidxs):
    previdx = NONE_ORDER        # -1
    for idxs in sameoffidxs:
        i = bisect_left(idxs, idx)
        while i > 0 and idxs[i-1] > previdx:
            i -= 1
            ins = instructions[idxs[i]]
            if not is_arimetic(ins):
                continue
            result = ins.execute()
            if value == result:
                previdx = idxs[i]
                break
    return previdx


def build_datagraph(instructions, offset2ins):
    datagraph = [[] for _ in instructions]
    for i, ins in enumerate(instructions):
        for offsets, value in zip(ins.offsets, ins.values):
            sameoffidxs = (offset2ins[off] for off in offsets if off != NONE_OFFSET)
            previdx = previous_instruction(instructions, i, value, sameoffidxs)
            datagraph[i].append(previdx)
            if previdx != NONE_ORDER:
                pass
                #print("\"{}\" -> \"{}\";".format(ins.asm, instructions[previdx].asm))
    return datagraph


def build_cmpgraph(instructions):
    pass


def groupby_offset(instructions):
    offset2ins = {}
    for i, ins in enumerate(instructions):
        for offset in set(itertools.chain(*ins.offsets)):
            if offset == NONE_OFFSET:
                continue
            if offset not in offset2ins:
                offset2ins[offset] = [i]
            else:
                offset2ins[offset].append(i)
    return offset2ins


def groupby_addr(instructions):
    addr2ins = OrderedDict()
    for i, ins in enumerate(instructions):
        addr = ins.addr
        if addr not in addr2ins:
            addr2ins[addr] = [i]
        else:
            addr2ins[addr].append(i)
    return addr2ins


def is_original(value, offset, input_):
    return all(off and get_byte(value, i) == input_[off] for i, off in enumerate(offset))


def symbolize_value(value, offset, input_):
    pass


def symbolic():
    pass


def concolic_execute(instructions, input_):
    datagraph = build_datagraph(instructions)
    cmpgraph = build_cmpgraph(instructions)
    for i, ins in enumerate(instructions):
        pass

def plot_datagraph(instructions, datagraph, outstrm=sys.stdout):
    strm = outstrm
    if isinstance(outstrm, str):    # fname
        strm = open(outstrm, 'w')

    print("digraph DG {", file=strm)
    for i, ins in enumerate(instructions):
        for k in datagraph[i]:
            if k == NONE_ORDER:
                continue
            preins = instructions[k]
            print("\t\"{}: {}\" -> \"{}: {}\";".format(i, ins.asm, k, preins.asm), file=strm)
    print("}", file=strm)

    if isinstance(outstrm, str):
        strm.close()

# main
trace_file = sys.argv[1]

instructions = parse_trace_file(trace_file)
offset2ins = groupby_offset(instructions)
addr2ins = groupby_addr(instructions)
datagraph = build_datagraph(instructions, offset2ins)
plot_datagraph(instructions, datagraph, 'bc.dot')
#for off, idxs in offset2ins.items():
#    for i in idxs:
#        ins = instructions[i]
#        print(off, ins.addr, ins.asm, ins.offsets)

#groupby_addr(trace_file)

#instructions = parse_trace_file(trace_file)

#print("ins: ", len(instructions))

#for addr, ins in instructions.items():
#    print(addr, ins.asm, ins.loffsets, ins.roffsets, ins.loperands, ins.roperands)
