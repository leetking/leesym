#!/usr/bin/env python3

import os
import re
import sys
import heapq
import struct
import operator
import argparse
import itertools
from random import randint
from collections import OrderedDict
from bisect import bisect_left

from viztracer import VizTracer

import z3

from leetaint import leetaint

be_quiet = False
enable_debug = True
OPERAND_DISTANCE_MAX = 200   # datagraph 操作数来源最多向上条数
LOOPINS_MAX = 8              # 目前调小这个以便处理循环中的校验和算法 TODO 后续加入校验判断识别，以跳过运算
CKSUM_MIN_BYTES = 64         # 一个操作数依赖多个字节认为是校验和

NONE_OFFSET = -1
NONE_ORDER  = -1

parser = argparse.ArgumentParser(prog='leesym', description='concolic executtion to get new seeds')
parser.add_argument('-s', '--server',
        dest='server_mode',
        action='store_true',
        default=False,
        help="server mode with stdin and stdout")
parser.add_argument('-i', '--input', dest='seed_file', help='A seed file')
parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', default=False, help='suppress message output')
parser.add_argument('--detect-struct',
        dest='detect_struct',
        action='store_true',
        default=False,
        help='detect input\'s structure')
parser.add_argument('-p', '--plot', dest='dot_file', help='plot trace file to this file')
parser.add_argument('-t', '--trace', dest='trace_file', help='A record file from leetaint')
parser.add_argument('-o', '--outdir', dest='output_dir', help='An output directory')
parser.add_argument('cmd', nargs='*', help='cmd')


def debug(*args, **kargs):
    if enable_debug and not be_quiet:
        print("DEBUG: ", *args, **kargs, file=sys.stderr)


def warn(*args, **kargs):
    if not be_quiet:
        print("WARN:", *args, **kargs, file=sys.stderr)


def info(*args, **kargs):
    if not be_quiet:
        print("INFO:", *args, **kargs, file=sys.stderr)


def int_fromhex(s: str) -> int:
    """从小端序表示的 hex 字符串中获取整数
    0a000000 => 10
    """
    return int.from_bytes(bytes.fromhex(s), "little")


# 整数按照二进制模式解释 (reinterpret) 为 IEE754 double
def int_as_float(uv: int, size=64):
    # 统一和 Intel 内部小端序一致
    uv = uv & ((1<<size)-1)
    return struct.unpack('<d', uv.to_bytes(8, 'little'))[0]


# 和 int_as_float 相反
def float_as_int(fp: float):
    return int.from_bytes(struct.pack('<d', fp), 'little')


def signed(uv, size):
    return uv | (-(uv & (1<<(size-1))))


def unsigned(iv, size):
    return iv + (1<<size)


def guess_singed(uv, size):
    # 0xffff as unsigned
    return (uv & (1<<(size-1))) and (uv != ((1<<size)-1))


def get_byte(num, idx):
    # int.to_bytes(1, 'little')
    return (num >> (8*idx)) & 0xff


def subpart(bitvec, start, end):
    size = bitvec.size()
    hi = size - start - 1
    lo = size - end
    # [hi, lo]
    return z3.Extract(hi, lo, bitvec)


COND_UNSPPORT = 0xff  # Unspport now, e.g. js
COND_EQ = 0x1   # ==
COND_NE = 0x2   # !=
COND_LT = 0x3   # <
COND_LE = 0x4   # <=
COND_GT = 0x5   # >
COND_GE = 0x6   # >=

class Instruction:
    @staticmethod
    def _is_condjmp(asm):
        ins = asm.split()[0]
        if 'j' != ins[0]:
            return False
        if ins in ('jl', 'jnge',   # <
                   'jle', 'jng',   # <=
                   'jg',  'jnle',  # >
                   'jge', 'jnl',   # >=
                   'jz',   'je',   # ==
                   'jnz',  'jne',  # !=
                   'jb',   'jnae', # <
                   'jbe',  'jna',  # <=
                   'ja',   'jnbe', # >
                   'jae',  'jnb',  # >=
                   'js',   'jns',  # SF is set
                   'jp',   'jnp'): # PF is set
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
        if ins in ('add', 'adc', 'sub', 'sbb', 'mul', 'imul', 'div', 'idiv',
                   'inc', 'dec',
                   'not', 'and', 'or', 'xor', 'pxor', 'pand', 'por',
                   'shr', 'shl', 'lea',
                   'ror', 'rol', 'sar', 'sal', 'bswap',
                   'addsd', 'subsd',
                   'pcmpeqb', 'pcmpeqw', 'pcmpeqd', # XMM 相等比较指令, 1b, 2b, 4b
                   'pcmpgtb', 'pcmpgtw', 'pcmpgtd',):
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
    @staticmethod
    def ror(val, shift, size):
        shift %= size
        return (val>>shift) | (val<<(size-shift))

    @staticmethod
    def symror(symval, shift, size):
        shift %= size
        return z3.LShR(symval, shift) | (symval<<(size-shift))

    @staticmethod
    def rol(val, shift, size):
        shift %= size
        return ArithmeticIns.ror(val, size - shift, size)

    @staticmethod
    def symrol(symval, shift, size):
        shift %= size
        return ArithmeticIns.symror(symval, size - shift, size)

    @staticmethod
    def idiv(a, b, size):
        # 采用 Intel 下的符号除法规则 ceil(a/b)
        # Python 的为 floor(a/b)
        return unsigned(int(signed(a, size) / signed(b, size)), size)

    @staticmethod
    def sar(uv, shift, size):
        #assert size and size%8 == 0
        # Python 中 >> 就是算术右移位
        return unsigned(signed(uv, size) >> shift, size)

    @staticmethod
    def bswap(symval, size):
        assert symval.size() == 8*size
        return z3.Concat(*reversed(tuple(subpart(symval, i*8, (i+1)*8) for i in range(size))))

    ops = {
        #'not': operator.not_,      # 按bits操作
        #'lea': None,
        #'ror': None,               # 循环右移
        #'rol': None,
        #'shr': operator.rshift,    # 逻辑右移
        #'idiv': None,
        #'div': None,
        #'bswap': None,             # 按字节交换
        #'addsd': None,             # addsd xmm0, xmm1 低 64 为double浮点数运算. sd: scale double, pd: packed double
        #'subsd': None,             # 类似 addsd
        #'pcmpeqb': None,           # xmm 指令集，按照字节比较，相等置目标字节为 FF，否则为 0
        'add': operator.add,
        'adc': operator.add,        # 加上 CF 标志位的加法
        'sub': operator.sub,
        'sbb': operator.sub,        # 减去 CF 标志位的减法，用于实现操作寄存器长度的减法操作. e.g. 32 模拟 64 位运算
        'mul': operator.mul,
        'imul': operator.mul,
        'and': operator.and_,
        'pand': operator.and_,      # MMX 指令
        'or': operator.or_,
        'por': operator.or_,
        'xor': operator.xor,
        'pxor': operator.xor,
        'shl': operator.lshift,
        'sal': operator.lshift,     # 算术左移
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
        if self._result != None:
            return self._result
        ins = self.asm.split()[0]
        values = self.values
        if ins == 'not':
            result = ~values[0]
        elif ins == 'inc':
            result = values[0]+1
        elif ins == 'dec':
            result = values[0]-1
        elif ins == 'lea':
            assert 4 == len(values)
            result = values[0] + values[1] * values[2] + values[3]
        elif ins == 'ror':
            result = ArithmeticIns.ror(values[0], values[1], 8*self.size)
        elif ins == 'rol':
            result = ArithmeticIns.rol(values[0], values[1], 8*self.size)
        elif ins == 'sar':  # 算术右移，符号扩展
            result = ArithmeticIns.sar(values[0], values[1], 8*self.size)
        elif ins == 'shr':
            result = values[0] >> values[1]
        elif ins == 'idiv':
            result = ArithmeticIns.idiv(values[0], values[1], 8*self.size)
        elif ins == 'div':
            result = values[0] // values[1]
        elif ins == 'bswap':
            assert self.size in (4, 8)
            result = int.from_bytes(values[0].to_bytes(self.size, 'little'), 'big')
        elif ins == 'addsd':
            assert 8 == self.size
            result = float_as_int(int_as_float(values[0]) + int_as_float(values[1]))
            debug("size: {}, ins: {}, v0: {} v1: {} rst: {}".format(self.size, self.asm, values[0], values[1], result))
        elif ins == 'subsd':
            assert 8 == self.size
            result = float_as_int(int_as_float(values[0]) - int_as_float(values[1]))
            debug("size: {}, ins: {}, v0: {} v1: {} rst: {}".format(self.size, self.asm, values[0], values[1], result))
        elif ins in ('pcmpeqb', 'pcmpeqw', 'pcmpeqd', 'pcmpgtb', 'pcmpgtw', 'pcmpgtd'):
            result = 0x0
            warn("XMM instruction {} isn't support".format(ins))
            debug("size: {}, ins: {}, v0: {} v1: {} rst: {}".format(self.size, self.asm, values[0], values[1], result))
        elif ins in ArithmeticIns.ops:
            result = ArithmeticIns.ops[ins](values[0], values[1])
            if ins in ('pxor', 'pand', 'por'):
                debug("size: {}, ins: {}, v0: {} v1: {} rst: {}".format(self.size, self.asm, values[0], values[1], result))
        else:
            raise ValueError("Unspport instruction {}".format(self.asm))
        # fixed size, and convert signed to unsigned for sub, sbb
        self._result = result & ((1<<(8*self.size))-1)
        return self._result

    @property
    def expression(self):
        assert self._expression != None
        return self._expression

    # 默认的 <, >, /, <<, >> 都是有符号操作，提供了 Uxx/Lxx 的操作默认都是有符号
    # 其余是无符号
    def symbolize(self, symvals):
        for sym in symvals:
            assert self.size*8 == sym.size()
        exp = None
        ins = self.asm.split()[0]
        values = self.values
        if ins == 'not':
            exp = ~symvals[0]
        elif ins == 'inc':
            exp = symvals[0]+1
        elif ins == 'dec':
            exp = symvals[0]-1
        elif ins == 'lea':
            assert 4 == len(values)
            exp = symvals[0] + symvals[1] * values[2] + values[3]
        elif ins == 'ror':
            exp = ArithmeticIns.symror(symvals[0], values[1], 8*self.size)
        elif ins == 'rol':
            exp = ArithmeticIns.symrol(symvals[0], values[1], 8*self.size)
        elif ins == 'sar':      # 逻辑右移位，z3 默认为符号右移和 Python 一致
            exp = symvals[0] >> values[1]
        elif ins == 'shr':
            exp = z3.LShR(symvals[0], values[1])
        elif ins == 'idiv':
            # TODO 替换 symvals[1] 为具体值，z3 默认为有符号除法
            exp = symvals[0] / symvals[1]
        elif ins == 'div':
            exp = z3.UDiv(symvals[0], symvals[1])
        elif ins == 'bswap':
            assert self.size in (4, 8)
            exp =ArithmeticIns.bswap(symvals[0], self.size)
        elif ins in ('addsd', 'subsd'):
            assert 8 == self.size
            # 浮点数运算采用具体值
            exp = z3.BitVec(self.execute(), 8*self.size)
            debug("size: {}, ins: {}, v0: {} v1: {} rst: {}".format(self.size, self.asm, symvals[0], symvals[1], exp))
        elif ins in ('pcmpeqb', 'pcmpeqw', 'pcmpeqd', 'pcmpgtb', 'pcmpgtw', 'pcmpgtd'):
            exp = z3.BitVec(0, 8*self.size)
            warn("XMM instruction {} isn't support".format(ins))
            debug("size: {}, ins: {}, v0: {} v1: {} rst: {}".format(self.size, self.asm, symvals[0], symvals[1], exp))
        elif ins in ArithmeticIns.ops:
            exp = ArithmeticIns.ops[ins](symvals[0], symvals[1])
        else:
            raise ValueError("Unspport instruction {}".format(self.asm))
        #self._expression = z3.simplify(exp)
        self._expression = exp
        return exp


def is_arimetic(ins):
    return isinstance(ins, ArithmeticIns)


def is_division(ins):
    divs = ('div', 'idiv')
    name = ins.asm.split()[0]
    return name in divs


class CondJumpIns:
    signed_ins = (
        'jl', 'jnge',   # <
        'jle', 'jng',   # <=
        'jg',  'jnle',  # >
        'jge', 'jnl',   # >=
    )
    unsigned_ins = (
        'jz',   'je',   # ==
        'jnz',  'jne',  # !=
        'jb',   'jnae', # <
        'jbe',  'jna',  # <=
        'ja',   'jnbe', # >
        'jae',  'jnb',  # >=
    )
    def __init__(self, addr, asm):
        self.addr = addr
        self.asm = asm

    @property
    def signed(self):
        ins = self.asm.split()[0]
        if ins in CondJumpIns.signed_ins:
            return True
        if ins in CondJumpIns.unsigned_ins:
            return False
        if ins in ('js', 'jns', 'jp', 'jnp'):
            warn("Ignore condition jump {}.".format(ins))
            return False
        raise ValueError("Unspport instruction {}".format(ins))

    @property
    def condition(self):
        ins = self.asm.split()[0]
        if ins in ('jz', 'je'):
            return COND_EQ
        if ins in ('jnz', 'jne'):
            return COND_NE
        if ins in ('jl', 'jnge', 'jb', 'jnae'):
            return COND_LT
        if ins in ('jle','jng', 'jbe', 'jna'):
            return COND_LE
        if ins in ('jg', 'jnle', 'ja', 'jnbe'):
            return COND_GT
        if ins in ('jge', 'jnl', 'jae', 'jnb'):
            return COND_GE
        if ins in ('js', 'jns', 'jp', 'jnp'):
            warn("Ignore condition jump {}.".format(ins))
            return COND_UNSPPORT
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
        None: ('??', lambda a, b: True),
    }
    def __init__(self, addr, asm, size, offsets, values):
        self.addr = addr
        self.asm = asm
        self.size = size
        self.offsets = offsets
        self.values = values
        self.condition = None
        self.signed = None
        self._result = None
        self._expression = None

    def strcond(self):
        if self.condition == None:
            warn("Compare doesn't set condition. (0x{:x} {})".format(self.addr, self.asm))
        if self.condition not in CompareIns.conds:
            raise ValueError("Unexpected condition in CompareIns")
        return CompareIns.conds.get(self.condition)[0]

    def guess_condition(self):
        assert self.condition == None or self.condition == COND_UNSPPORT
        assert 2 == len(self.values)
        assert self.signed != None
        ins = self.asm.split()[0]
        size = 8*self.size
        values = self.values
        v0 = signed(values[0], size) if self.signed else values[0]
        v1 = signed(values[1], size) if self.signed else values[1]
        if ins in ('cmp'):
            if randint(0, 99) >= 50:
                return COND_EQ if v0 == v1 else COND_NE
            else:
                if v0 < v1:
                    return COND_LE
                if v0 > v1:
                    return COND_GT
                if v0 == v1:
                    return COND_EQ
        elif ins in ('test'):
            return COND_EQ if v0 == v1 else COND_NE
        raise ValueError("Unknow compare instruction {}".format(ins))

    def execute(self):
        assert 2 == len(self.values)
        if self._result != None:
            return self._result
        values = self.values
        size = 8*self.size
        if self.signed == None:
            warn("Unknow sign, guess by operands")
            self.signed = guess_singed(values[0], size) or guess_singed(values[1], size)
        if self.condition == None or self.condition == COND_UNSPPORT:
            warn("Unknow condition, guess by operands");
            self.condition = self.guess_condition()
        v0 = signed(values[0], size) if self.signed else values[0]
        v1 = signed(values[1], size) if self.signed else values[1]
        ins = self.asm.split()[0]
        if self.condition not in CompareIns.conds:
            raise ValueError("Unexpected condition in CompareIns")
        self._result = CompareIns.conds[self.condition][1](v0, v1)
        return self._result

    @property
    def expression(self):
        assert self._expression != None
        return self._expression

    def symbolize(self, symvals):
        assert 2 == len(symvals)
        cond = self.execute()
        if self.condition not in CompareIns.conds:
            raise ValueError("Unexpected condition in CompareIns")
        exp = CompareIns.conds[self.condition][1](symvals[0], symvals[1])
        if cond == False:
            exp = z3.Not(exp)
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


def previous_compare(instructions, limit=5):
    len_ = len(instructions)
    for i in range(-1, max(-limit, -len_)-1, -1):
        if is_compare(instructions[i]):
            return len_ + i
    return NONE_ORDER


def parse_trace_file(fname):
    # 记录全部指令，以地址为记录
    instructions = []
    with open(fname, 'r') as tf:
        for trace in tf:
            ins = Instruction.from_trace(trace)
            # discard condtion jump
            if is_condjmp(ins):
                prevcmpidx = previous_compare(instructions)
                if prevcmpidx == NONE_ORDER:
                    warn("Single condtion jump. (0x{:x}: {})".format(ins.addr, ins.asm))
                else:
                    instructions[prevcmpidx].condition = ins.condition
                    instructions[prevcmpidx].signed = ins.signed
            else:
                instructions.append(ins)
    return instructions


def find_same_operand(ins, offset, value):
    for i, (offset2, value2) in enumerate(zip(ins.offsets, ins.values)):
        if value2 == value and offset2 == offset:
            return i
    return NONE_ORDER


def previous_instruction(datagraph, instructions, idx, offset, value, sameoffidxes):
    previdx = NONE_ORDER        # -1
    for idxes in sameoffidxes:
        i = bisect_left(idxes, idx)
        end = max(0, i - OPERAND_DISTANCE_MAX)
        while i > end and idxes[i-1] > previdx:
            i -= 1
            ins = instructions[idxes[i]]
            # check operands
            opidx = find_same_operand(ins, offset, value)
            if opidx != NONE_ORDER:
                new_previdx = datagraph[idxes[i]][opidx]
                if new_previdx > previdx:
                    previdx = new_previdx
                    break
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
        ins.depth = 0
        ins.depth_prev = NONE_ORDER
        for offset, value in zip(ins.offsets, ins.values):
            sameoffidxes = (offset2idxes[off] for off in offset if off != NONE_OFFSET)
            previdx = previous_instruction(datagraph, instructions, i, offset, value, sameoffidxes)
            datagraph[i].append(previdx)
            # 构建深度图
            if previdx != NONE_ORDER:
                previns = instructions[previdx]
                if previns.depth + 1 > ins.depth:
                    ins.depth = previns.depth + 1
                    ins.depth_prev = previdx
    return datagraph


def is_operand_i2s():
    pass


def detect_multibytes_dependent(instructions, datagraph):
    for i, ins in enumerate(instructions):
        ins.multibytes = [set() for _ in ins.offsets]
        for k, (offset, value) in enumerate(zip(ins.offsets, ins.values)):
            previdx = datagraph[i][k]
            operand_bytes = set(x for x in offset if x != NONE_OFFSET)
            if previdx == NONE_ORDER:
                ins.multibytes[k] = operand_bytes
            else:
                ins.multibytes[k] = operand_bytes | set(itertools.chain(*instructions[previdx].multibytes))
        if is_compare(ins):
            pass


def is_operand_field(offset):
    pass


def gather_magic_field(instructions):
    pass


def gather_checksum_field(instructions):
    pass


def gather_length_field(instructions):
    pass


# TODO，对循环的最后一次实行符号化，以求边界
def optimize_instruction(instructions, datagraph, addr2idxes, loopinsmax=LOOPINS_MAX):
    cnts = [NONE_ORDER for _ in instructions]
    for i, ins in enumerate(instructions):
        assert ins.depth != None and ins.depth_prev != None
        addr = ins.addr
        addrcnt = len(addr2idxes[addr])
        if addrcnt <= loopinsmax or ins.depth <= loopinsmax:
            ins.optimized = False
            continue
        # maybe need optimize
        k = ins.depth_prev
        if cnts[k] != NONE_ORDER:
            cnts[i] = cnts[k] + 1
        else:
            c = 1
            while k != NONE_ORDER:
                prevaddr = instructions[k].addr
                if addr == prevaddr:
                    c += 1
                k = instructions[k].depth_prev
            cnts[i] = c
        ins.optimized = True if cnts[i] > loopinsmax else False


def build_cmpgraph(instructions):
    graph = [NONE_ORDER for _ in instructions]
    prev = NONE_ORDER
    for i, ins in enumerate(instructions):
        graph[i] = prev
        if is_compare(ins):
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


def is_original(value, offset, seed):
    return all(off == NONE_OFFSET or get_byte(value, i) == seed[off] for i, off in enumerate(offset))


def enable_sign_extend(val, offset, idx):
    assert offset[idx] != NONE_OFFSET
    ext = 0xff if get_byte(val, idx) & 0x80 else 0x0
    return all(offset[i] == NONE_OFFSET and get_byte(val, i) == ext for i in range(idx+1, len(offset)))


def symbolize_value(value, offset):
    assert offset
    exp = None
    len_ = len(offset)
    for i, off in enumerate(offset):
        if off == NONE_OFFSET:
            byte = z3.BitVecVal(get_byte(value, i), 8)
        else:
            byte = z3.BitVec("b{}".format(off), 8)
            if i+1 < len_ and enable_sign_extend(value, offset, i):
                byte = z3.SignExt(8*(len_ - i - 1), byte)
                exp = z3.Concat(byte, exp) if exp != None else byte
                return exp
        exp = z3.Concat(byte, exp) if exp != None else byte
    return z3.simplify(exp)
    #return exp


def is_offset_empty(offsets):
    return not offsets or all(off == NONE_OFFSET for off in offsets)


def concolic_execute(instructions, seed):
    offset2idxes = groupby_offset(instructions)
    addr2idxes = groupby_addr(instructions)
    info("buiding datagraph ...")
    datagraph = build_datagraph(instructions, offset2idxes)
    cmpgraph = build_cmpgraph(instructions)
    # 优化循环指令
    optimize_instruction(instructions, datagraph, addr2idxes)
    ret = set()
    path_contraintion = {}
    for i, ins in enumerate(instructions):
        insbits = 8*ins.size
        # for every operand
        symvals = [None for _ in ins.offsets]
        for k, (offset, value) in enumerate(zip(ins.offsets, ins.values)):
            previdx = datagraph[i][k]
            symval = None
            if not is_offset_empty(offset) and not ins.optimized:
                if previdx == NONE_ORDER and is_original(value, offset, seed):
                    symval = symbolize_value(value, offset)
                elif previdx != NONE_ORDER:
                    prevexp = instructions[previdx].expression
                    if prevexp.size() < insbits:
                        symval = z3.SignExt(insbits - prevexp.size(), prevexp)
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
            symvals[k] = symval

        if is_compare(ins):
            prevpcidx = cmpgraph[i]
            exp = ins.symbolize(symvals)      if not ins.optimized else True
            pc = path_contraintion[prevpcidx] if previdx != NONE_ORDER else []
            path_contraintion[i] = pc + [exp] if not ins.optimized else pc
            # 突破不等交给 Fuzzer，而不是 SymExe. 没有优化的指令才进行计算
            if not (ins.condition == COND_EQ and ins.execute() == True) and not ins.optimized:
                info("Now begin checking compare sat, with exps:", len(pc)+1)
                solver = z3.Solver()
                solver.add(z3.Not(exp), *pc)
                rst = solver.check()
                if rst == z3.sat:
                    model = solver.model()
                    if len(model):
                        ret.add(str(model))
                    debug(model)
                elif rst == z3.unsat:
                    info("Unsat. {}: {}".format(i, Instruction.beautify(ins)))
                elif rst == z3.unknown:
                    info("Can't resolve. {}: {}".format(i, Instruction.beautify(ins)))
                else:
                    raise ValueError("Unknow result solver returned")
        elif is_jump(ins):
            pass
        elif is_arimetic(ins):
            if is_division(ins) and not ins.optimized:
                prevpcidx = cmpgraph[i]
                pc = path_contraintion[prevpcidx] if previdx != NONE_ORDER else []
                info("Now begin checking div sat, with exps:", len(pc)+1)
                solver = z3.Solver()
                solver.add(0 == symvals[1], *pc)
                rst = solver.check()
                if rst == z3.sat:
                    model = solver.model()
                    if len(model):
                        ret.add(str(model))
                    debug(model)
                elif rst == z3.unsat:
                    info("Unsat. {}: {}".format(i, Instruction.beautify(ins)))
                elif rst == z3.unknown:
                    info("Can't resolve. {}: {}".format(i, Instruction.beautify(ins)))
                else:
                    raise ValueError("Unknow result solver returned")
            # symbolize this expression
            ins.symbolize(symvals)
        else:
            raise ValueError("Unspport instruction {}".format(ins.asm))

    return list(ret)


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


def writefile(bytes_, file):
    with open(file, 'wb') as fp:
        fp.write(bytes_)


def save_all_testcases(result, seed, outdir):
    name_len = 500
    generated_testcases = []
    pat = r'b(\d+)\s*=\s*(\d+)'
    os.makedirs(outdir, exist_ok=True)
    for rst in result:
        input_ = bytearray(seed)
        repls = [(int(s), int(v)) for s, v in re.findall(pat, rst)]
        repls.sort(key=operator.itemgetter(0))
        name = '#'.join("{:02x}@b{}".format(v, s) for s, v in repls)
        name = name[:name_len]  # 防止操作操作系统最大文件长度
        for s, v in repls:
            assert (v & (~0xff)) == 0x0
            input_[s] = v
        fnamepath = os.path.join(outdir, name)
        if os.path.exists(fnamepath):
            warn("{} exists, skip".format(name))
        else:
            writefile(input_, fnamepath)
            generated_testcases.append(fnamepath)
    return generated_testcases


def server_mode():
    # 握手
    type_cmdline = 'cmdline:'
    type_outdir = 'outdir:'
    type_seed = 'seed:'
    cmdline = input().strip()
    if not cmdline.startswith(type_cmdline):
        return 101
    cmdline = cmdline[len(type_cmdline):].lstrip()

    outdir = input().strip()
    if not outdir.startswith(type_outdir):
        return 101
    outdir = outdir[len(type_outdir):].lstrip()
    print('Ok')

    loop_cnt = 0
    while True:
        try:
            request = input()
        except (KeyboardInterrupt, EOFError):
            print('Bye')
            break
        if request.startswith('Bye'):
            print('Bye')
            break
        if not request.startswith(type_seed):
            print('error: invalid type')
            continue
        seed_file = request[len(type_seed):].strip()

        req_outdir = os.path.join(outdir, '{:06}'.format(loop_cnt))

        if not leetaint(seed_file, req_outdir, cmdline):
            print("error: leetaint fails")
            continue
        trace_file = os.path.join(req_outdir, 'trace.txt')
        seed = readfile(seed_file)
        testcasepath = os.path.join(req_outdir, 'testcases')
        instructions = parse_trace_file(trace_file)
        result = concolic_execute(instructions, seed)
        saved_files = save_all_testcases(result, seed, testcasepath)
        print("generated: ", len(saved_files))
        print("generated: ", len(saved_files), file=sys.stderr)
        for no, fpath in enumerate(saved_files):
            print("input{}: {}".format(no, fpath))
            print("input{}: {}".format(no, fpath), file=sys.stderr)

        loop_cnt += 1

    return 0


def main():
    args = parser.parse_args()

    if args.quiet:
        global be_quiet
        be_quiet = True

    # server mode
    if args.server_mode:
        server_mode()
        return 0

    # plot data graph
    if args.dot_file and args.cmd:
        instructions = parse_trace_file(args.cmd[0])
        offset2idxes = groupby_offset(instructions)
        datagraph = build_datagraph(instructions, offset2idxes)
        detect_multibytes_dependent(instructions, datagraph)
        plot_datagraph(instructions, datagraph, args.dot_file)
        return 0

    if not args.seed_file:
        parser.print_usage()
        return 101

    # trace file
    if args.trace_file:
        if args.detect_struct:
            pass
        else:
            seed = readfile(args.seed_file)
            instructions = parse_trace_file(args.trace_file)
            result = concolic_execute(instructions, seed)
        return 0

    # taint + concolic exe
    if args.output_dir and args.cmd:
        if not leetaint(args.seed_file, args.output_dir, args.cmd):
            print("leetaint fails")
            return 102
        trace_file = os.path.join(args.output_dir, 'trace.txt')
        seed = readfile(args.seed_file)
        with VizTracer():
            testcasepath = os.path.join(args.output_dir, 'testcases')
            instructions = parse_trace_file(trace_file)
            result = concolic_execute(instructions, seed)
            saved_files = save_all_testcases(result, seed, testcasepath)
        return 0

    # invalid useage
    parser.print_usage()


if __name__ == '__main__':
    main()
