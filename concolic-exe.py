#!/usr/bin/env python3

import sys
import re
import itertools
import operator
import z3
from collections import OrderedDict
from bisect import bisect_left


NONE_OFFSET = -1
NONE_ORDER  = -1


def warn(*args, **kargs):
    print("WARN:", *args, **kargs, file=sys.stderr)


def info(*args, **kargs):
    print("INFO:", *args, **kargs, file=sys.stderr)


def int_fromhex(s: str) -> int:
    """从小端序表示的 hex 字符串中获取整数
    0a000000 => 10
    """
    return int.from_bytes(bytes.fromhex(s), "little")


def get_byte(num, idx):
    # int.to_bytes(1, 'little')
    return (num >> (8*idx)) & 0xff


COND_UNSPPORT = 0  # Unspport now, e.g. js
COND_EQ = 0x1   # ==
COND_NE  = 0x2   # !=
COND_LT  = 0x3   # <
COND_LE  = 0x4   # <=
COND_GT = 0x5   # >
COND_GE = 0x6 # >=


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
        warn("Maybe forget condition jump: ", asm)
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
        raise ValueError("Unspport instruction {}".format(asm))

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

    @staticmethod
    def beautify(ins):
        result = ""
        if is_arimetic(ins):
            result = " => {}".format(ins.execute())
        name = ins.asm.split()[0]
        if is_compare(ins):
            name = ins.strcond()
        values = ", ".join("{}".format(v) for v in ins.values)
        return f"{name} {values}{result}"


class ArithmeticIns:
    ops = {
        'add': operator.add,
        'sub': operator.sub,
        'mul': operator.mul,
        'imul': operator.mul,
        'div': operator.floordiv,
        #'not': operator.not_,      # 按bits操作
        'and': operator.and_,
        'or': operator.or_,
        'xor': operator.xor,
        'shr': operator.rshift,     # 逻辑移位
        'shl': operator.lshift,
        #'lea': _,
    }

    def __init__(self, addr, asm, size, offsets, values):
        self.addr = addr
        self.asm = asm
        self.size = size
        self.offsets = offsets
        self.values = values
        self._result = None
        self._expression = None

    def execute(self):
        if self._result:
            return self._result
        ins = self.asm.split()[0]
        values = self.values
        if ins == 'not':
            assert 1 == len(values)
            result = ~values[0]
        elif ins in ('add', 'sub', 'mul', 'imul', 'div',
                     'and', 'or', 'xor', 'shr', 'shl'):
            assert 2 == len(values)
            result = ArithmeticIns.ops[ins](values[0], values[1])
        elif ins == 'lea':
            assert 4 == len(values)
            result = values[0] + values[1] * values[2] + values[3]
        else:
            raise ValueError("Unspoort instruction {}".format(self.asm))
        # fixed size
        self._result = result & ((1<<(8*self.size))-1)
        return self._result

    @property
    def expression(self):
        assert self._expression != None
        return self._expression

    def symbolize(self, symvals):
        for sym in symvals:
            assert self.size*8 == sym.size()
        exp = None
        ins = self.asm.split()[0]
        values = self.values
        if ins == 'not':
            assert 1 == len(symvals)
            exp = ~symvals[0]
        elif ins in ('add', 'sub', 'mul', 'imul', 'div', 'and', 'or', 'xor'):
            assert 2 == len(symvals)
            exp = ArithmeticIns.ops[ins](symvals[0], symvals[1])
        elif ins in ('shr', 'shl'):
            assert 2 == len(symvals)
            assert 2 == len(values)
            exp = ArithmeticIns.ops[ins](symvals[0], values[1])
        elif ins == 'lea':
            assert 2 == len(symvals)
            assert 4 == len(values)
            exp = symvals[0] + symvals[1] * values[2] + values[3]
        else:
            raise ValueError("Unspoort instruction {}".format(self.asm))
        self._expression = exp
        return exp


def is_arimetic(ins):
    return isinstance(ins, ArithmeticIns)


def is_division(ins):
    divs = ('div')
    name = ins.asm.split()[0]
    return name in divs


class CondJumpIns:
    def __init__(self, addr, asm):
        self.addr = addr
        self.asm = asm

    @property
    def condition(self):
        ins = self.asm.split()[0]
        if ins == 'jz':
            return COND_EQ
        if ins == 'jnz':
            return COND_NE
        if ins in ('jl', 'jb'):
            return COND_LT
        if ins in ('jle', 'jbe'):
            return COND_LE
        if ins in ('ja', 'jnle', 'jnbe'):
            return COND_GT
        if ins in ('jnl', 'jnb'):
            return COND_GE
        if ins in ('js'):
            warn("Ignore condition jump: ", ins)
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
    conds = {
        COND_EQ: ('==', operator.eq),
        COND_NE: ('!=', operator.ne),
        COND_LT: ('<',  operator.lt),
        COND_LE: ('<=', operator.le),
        COND_GT: ('>',  operator.gt),
        COND_GE: ('>=', operator.ge),
        COND_UNSPPORT: ('??', lambda a, b: True),
    }
    def __init__(self, addr, asm, size, offsets, values):
        self.addr = addr
        self.asm = asm
        self.size = size
        self.offsets = offsets
        self.values = values
        self.condition = None
        self._expression = None

    def strcond(self):
        if self.condition == None:
            warn("Compare doesn't set condition. (0x{:x} {})".format(self.addr, self.asm))
        if self.condition == COND_EQ:
            return "=="
        if self.condition == COND_NE:
            return "!="
        if self.condition == COND_LT:
            return "<"
        if self.condition == COND_LE:
            return "<="
        if self.condition == COND_GT:
            return ">"
        if self.condition == COND_GE:
            return ">="
        # Unspport
        return "??"

    def execute(self):
        raise ValueError("Compare Instruction can't execute")

    @property
    def expression(self):
        assert self._expression != None
        return self._expression

    def symbolize(self, symvals):
        assert self.condition
        assert 2 == len(symvals)
        if self.condition == COND_UNSPPORT:
            warn("Unknow condition (0x{:x} {})".format(self.addr, self.asm))
        if self.condition not in CompareIns.conds:
            raise ValueError("Unexpected condition in CompareIns")
        exp = CompareIns.conds[self.condition][1](symvals[0], symvals[1])
        self._expression = exp
        return exp



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
        self._expression = None

    def execute(self):
        raise ValueError("Jump Instruction can't execute")

    def expression(self):
        pass

    def symbolize(self, symvals):
        pass


def is_jump(ins):
    return isinstance(ins, JumpIns)


def parse_trace_file(fname):
    # 记录全部指令，以地址为记录
    instructions = []
    with open(trace_file, 'r') as tf:
        for trace in tf:
            ins = Instruction.from_trace(trace)
            # discard condtion jump
            if is_condjmp(ins):
                if not instructions or not is_compare(instructions[-1]):
                    warn("Single condtion jump. (0x{:x}: {})".format(ins.addr, ins.asm))
                elif COND_UNSPPORT == ins.condition:
                    del instructions[-1]
                else:
                    assert COND_UNSPPORT != ins.condition
                    instructions[-1].condition = ins.condition
            else:
                instructions.append(ins)
    return instructions


def previous_instruction(instructions, idx, value, sameoffidxes):
    previdx = NONE_ORDER        # -1
    for idxes in sameoffidxes:
        i = bisect_left(idxes, idx)
        while i > 0 and idxes[i-1] > previdx:
            i -= 1
            ins = instructions[idxes[i]]
            if not is_arimetic(ins):
                continue
            result = ins.execute()
            if value == result:
                previdx = idxes[i]
                break
    return previdx


def build_datagraph(instructions, offset2idxes):
    datagraph = [[] for _ in instructions]
    for i, ins in enumerate(instructions):
        for offsets, value in zip(ins.offsets, ins.values):
            sameoffidxes = (offset2idxes[off] for off in offsets if off != NONE_OFFSET)
            previdx = previous_instruction(instructions, i, value, sameoffidxes)
            datagraph[i].append(previdx)
    return datagraph


def build_cmpgraph(instructions):
    graph = OrderedDict()
    prev = NONE_ORDER
    for i, ins in enumerate(instructions):
        if not is_compare(ins):
            continue
        graph[i] = prev
        prev = i
    return graph


def groupby_offset(instructions):
    offset2idxes = {}
    for i, ins in enumerate(instructions):
        for offset in set(itertools.chain(*ins.offsets)):
            if offset == NONE_OFFSET:
                continue
            if offset not in offset2idxes:
                offset2idxes[offset] = [i]
            else:
                offset2idxes[offset].append(i)
    return offset2idxes


def groupby_addr(instructions):
    addr2idxes = OrderedDict()
    for i, ins in enumerate(instructions):
        addr = ins.addr
        if addr not in addr2idxes:
            addr2idxes[addr] = [i]
        else:
            addr2idxes[addr].append(i)
    return addr2idxes


def is_original(value, offset, input_):
    return all(off == NONE_OFFSET or get_byte(value, i) == input_[off] for i, off in enumerate(offset))


def symbolize_value(value, offset):
    assert offset
    exp = None
    for i, off in enumerate(offset):
        if off == NONE_OFFSET:
            byte = z3.BitVecVal(get_byte(value, i), 8)
        else:
            byte = z3.BitVec("b{}".format(off), 8)
        exp = z3.Concat(byte, exp) if exp != None else byte
    #return z3.simplify(exp)
    return exp


def is_offset_empty(offsets):
    return not offsets or all(off == NONE_OFFSET for off in offsets)


def subpart(bitvec, start, end):
    #return z3.simplify(z3.Extract(bitvec))
    size = bitvec.size()
    hi = size - start - 1
    lo = size - end
    # [hi, lo]
    return z3.Extract(hi, lo, bitvec)


def concolic_execute(instructions, input_):
    offset2idxes = groupby_offset(instructions)
    addr2idxes = groupby_addr(instructions)
    datagraph = build_datagraph(instructions, offset2idxes)
    cmpgraph = build_cmpgraph(instructions)
    plot_datagraph(instructions, datagraph)
    #syminput = tuple(z3.BitVec("b{}".format(i) for i, _ in enumerate(input_)))
    path_contraintion = {}
    for i, ins in enumerate(instructions):
        insbits = 8*ins.size
        # for every operand
        symvals = []
        for k, (offset, value) in enumerate(zip(ins.offsets, ins.values)):
            previdx = datagraph[i][k]
            symval = None
            if not is_offset_empty(offset):
                if previdx == NONE_ORDER and is_original(value, offset, input_):
                    symval = symbolize_value(value, offset)
                elif previdx != NONE_ORDER:
                    prevexp = instructions[previdx].expression
                    if prevexp.size() < insbits:
                        symval = z3.Concat(z3.BitVecVal(0, insbits - prevexp.size()), prevexp)
                    elif prevexp.size() > insbits:
                        symval = subpart(prevexp, 0, insbits)
                    else:
                        symval = prevexp
                else:
                    # TODO 减少这种情况的发生
                    warn("Dependence chain is broken. {}: {}".format(i, Instruction.beautify(ins)))
                    symval = z3.BitVecVal(value, 8*ins.size)
            else:
                symval = z3.BitVecVal(value, 8*ins.size)
            #symval = z3.simplify(symval)
            symvals.append(symval)

        if is_compare(ins):
            prevpcidx = cmpgraph[i]
            exp = ins.symbolize(symvals)
            pc = []
            if prevpcidx != NONE_ORDER:
                pc += path_contraintion[prevpcidx]
            if ins.condition != COND_EQ:    # 突破不等交给 Fuzzer，而不是 SymExe
                solver = z3.Solver()
                solver.add(z3.Not(exp), *pc)
                rst = solver.check()
                if rst == z3.sat:
                    print(solver.model())
                elif rst == z3.unsat:
                    info("Unsat. {}: {}".format(i, Instruction.beautify(ins)))
                elif rst == z3.unknown:
                    info("Can't resolve. {}: {}".format(i, Instruction.beautify(ins)))
                else:
                    raise ValueError("Unknow result solver returned")
            path_contraintion[i] = pc + [exp]
        elif is_jump(ins):
            pass
        elif is_division(ins):
            pass
        elif is_arimetic(ins):
            # symbolize this expression
            ins.symbolize(symvals)
        else:
            raise ValueError("Unspport instruction {}".format(ins.asm))


def plot_datagraph(instructions, datagraph, outstrm=sys.stdout):
    strm = outstrm
    if isinstance(outstrm, str):    # fname
        strm = open(outstrm, 'w')

    print("digraph DG {", file=strm)
    for i, ins in enumerate(instructions):
        for k in datagraph[i]:
            if k == NONE_ORDER:
                print("\t\"{}: {}\";".format(i, Instruction.beautify(ins)), file=strm)
            else:
                preins = instructions[k]
                print("\t\"{}: {}\" -> \"{}: {}\";".format(i, Instruction.beautify(ins),
                                                           k, Instruction.beautify(preins)), file=strm)
    print("}", file=strm)

    if isinstance(outstrm, str):
        strm.close()

def readfile(file):
    with open(file, 'rb') as fp:
        return fp.read()    # read all content

# main
trace_file = sys.argv[1]
input_file = sys.argv[2]
input_ = readfile(input_file)

instructions = parse_trace_file(trace_file)

concolic_execute(instructions, input_)

#offset2idxes = groupby_offset(instructions)
#addr2idxes = groupby_addr(instructions)
#datagraph = build_datagraph(instructions, offset2idxes)
#cmpgraph = build_cmpgraph(instructions)
#for i, p in cmpgraph.items():
#    cur = instructions[i]
#    prv = instructions[p]
#    print("{}: {} -> {}: {}".format(i, Instruction.beautify(cur), p, Instruction.beautify(prv)))
#plot_datagraph(instructions, datagraph)
#for off, idxes in offset2ins.items():
#    for i in idxes:
#        ins = instructions[i]
#        print(off, ins.addr, ins.asm, ins.offsets)

#groupby_addr(trace_file)

#instructions = parse_trace_file(trace_file)

#print("ins: ", len(instructions))

#for addr, ins in instructions.items():
#    print(addr, ins.asm, ins.loffsets, ins.roffsets, ins.loperands, ins.roperands)
