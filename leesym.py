#!/usr/bin/env python3

import os
import re
import sys
import struct
import operator
import argparse
import itertools
import subprocess
from random import randint
from collections import OrderedDict, deque
from bisect import bisect_left

import z3

from leetaint import leetaint

OPERAND_DISTANCE_MAX = 200   # datagraph 操作数来源最多向上条数
LOOPINS_MAX = 16             # 目前调小这个以便处理循环中的校验和算法 TODO 后续加入校验判断识别，以跳过运算
                             # 从 8 调整到 16
CKSUM_MIN_BYTES = 64         # 一个操作数依赖多个字节认为是校验和

NONE_OFFSET = -1
NONE_ORDER  = -1

COND_UNSPPORT = 0xff  # Unspport now, e.g. jp
COND_EQ = 0x1   # ==
COND_NE = 0x2   # !=
COND_LT = 0x3   # <
COND_LE = 0x4   # <=
COND_GT = 0x5   # >
COND_GE = 0x6   # >=


be_quiet = False
enable_debug = True

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


def guess_signed(uv, size):
    # 0xffff as unsigned
    return (uv & (1<<(size-1))) and (uv != ((1<<size)-1))


def get_byte(num, idx):
    # int.to_bytes(1, 'little')
    return (num >> (8*idx)) & 0xff

def get_bytes(num, start, end):
    mask = (1<<((end-start)*8)) - 1
    return (num >> (8*start)) & mask


def subpart(bitvec, start, end):
    size = bitvec.size()
    hi = size - start - 1
    lo = size - end
    # [hi, lo]
    return z3.Extract(hi, lo, bitvec)

class InstructionErr(Exception):
    pass

class Operand:
    def __init__(self, offset, value, size):
        self._offset = offset
        self._value = value
        self._size = size

    @property
    def offset(self):
        return self._offset

    @property
    def value(self):
        return self._value

    @property
    def size(self):
        return self._size

    def subbyte(self, idx):
        assert 0 <= idx < self.size
        return Operand(self.offset[idx:idx+1], get_byte(self.value, idx), 1)

    def subpart(self, start, end):
        assert 0 <= start < end < self.size
        return Operand(self.offset[start:end], get_bytes(self.value, start, end), end-start)


class Instruction:
    width_suffix = {'b': 1, 'w': 2, 'd': 4, 'q': 8,}
    pcmpeq_ins = ('vpcmpeqb', 'vpcmpeqw', 'vpcmpeqd', 'vpcmpeqq',
                  'pcmpeqb', 'pcmpeqw', 'pcmpeqd', 'pcmpeqq')
    pcmpgt_ins = ('vpcmpgtb', 'vpcmpgtw', 'vpcmpgtd', 'vpcmpgtq',
                  'pcmpgtb', 'pcmpgtw', 'pcmpgtd', 'pcmpgtq')
    simd_ins = pcmpeq_ins + pcmpgt_ins

    @staticmethod
    def is_condjmp(ins):
        if not isinstance(ins, (CondJumpIns, str)):
            return False
        if isinstance(ins, CondJumpIns):
            return True
        if 'j' != ins[0]:
            return False
        name = ins.split()[0]   # 'ja'.split()[0] == 'ja'
        if CondJumpIns.contains(name):
            return True
        return False

    @staticmethod
    def is_jump(ins):
        if not isinstance(ins, (JumpIns, str)):
            return False
        if isinstance(ins, JumpIns):
            return True
        return 'jmp' == ins.split()[0]

    @staticmethod
    def is_compare(ins):
        if not isinstance(ins, (CompareIns, str)):
            return False
        if isinstance(ins, CompareIns):
            return True
        return ins in Instruction.pcmpeq_ins \
                or ins in Instruction.pcmpgt_ins \
                or CompareIns.contains(ins)

    @staticmethod
    def is_hard_compare(ins):
        if not Instruction.is_compare(ins):
            return False
        # 当前数据满足相等条件，或不满足不等条件
        easy = not ins.execute() and ins.condition == COND_NE \
               or ins.execute() and ins.condition == COND_EQ
        return not easy

    @staticmethod
    def is_arimetic(ins):
        if not isinstance(ins, (ArithmeticIns, str)):
            return False
        if isinstance(ins, ArithmeticIns):
            return True
        name = ins.split()[0]
        if ArithmeticIns.contains(name):
            return True
        return False

    @staticmethod
    def is_simd(ins):
        """SIMD Instruction"""
        if not isinstance(ins, str):
            return False
        name = ins.split()[0]
        return name in Instruction.simd_ins

    @staticmethod
    def is_splited_simd(ins):
        return getattr(ins, 'simd', False)

    @staticmethod
    def is_division(ins):
        if not isinstance(ins, (ArithmeticIns, str)):
            return False
        name = ins.name if isinstance(ins, ArithmeticIns) else ins.split()[0]
        return name in ('div', 'idiv')

    @staticmethod
    def _split_simd(addr, asm, size, offsets, values):
        name, *operands = asm.split()
        width = Instruction.width_suffix[name[-1]]
        if name in Instruction.pcmpeq_ins:
            name = 'test'
            cond = COND_EQ
        elif name in Instruction.pcmpgt_ins:
            name = 'cmp'
            cond = COND_GT
        else:
            raise InstructionErr("Unspport SIMD instruction {}".format(name))
        asm = ' '.join([name, *operands])
        ret = []
        for i in range(0, size, width):
            suboffsets = tuple(offset[i:i+width] for offset in offsets)
            subvalues = tuple(get_bytes(val, i, i+width) for val in values)
            ins = Instruction._classify(addr, asm, width, suboffsets, subvalues)
            ins.simd = True
            if Instruction.is_compare(ins):
                ins.condition = cond
            ret.append(ins)
        return ret

    @staticmethod
    def _classify(addr, asm, size=None, offsets=None, values=None, result=None):
        # TODO 重构此函数
        ins = asm.split()[0]
        if ins in ('cmp', 'test', 'cmpxchg'):
            return CompareIns(addr, asm, size, offsets, values)
        if ins in ('jmp'):
            return JumpIns(addr, asm, size, result, offsets, values)
        if Instruction.is_condjmp(ins):
            return CondJumpIns(addr, asm)
        if ins in ('add', 'adc', 'sub', 'sbb', 'mul', 'imul', 'div', 'idiv',
                   'inc', 'dec',
                   'not', 'and', 'or', 'xor', 'pxor', 'pand', 'por',
                   'shr', 'shl', 'lea',
                   'ror', 'rol', 'sar', 'sal', 'bswap',
                   'addsd', 'subsd'):
            return ArithmeticIns(addr, asm, size, offsets, values)
        if ins == 'rep' and asm.split()[1] in ('cmpsb', 'cmpsw', 'cmpsd'):
            return CompareIns(addr, asm, size, offsets, values)
        raise InstructionErr("Unspport instruction {}".format(asm))

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
        if Instruction.is_condjmp(asm):
            return Instruction._classify(addr, asm)
        if Instruction.is_jump(asm):
            result, offsets, *values = rest
        else:
            offsets, *values = rest
        offsets = parse_offsets(offsets)
        values = tuple(int_fromhex(v) for v in values if v)
        size = max(len(off) for off in offsets)
        if Instruction.is_simd(asm):
            return Instruction._split_simd(addr, asm, size, offsets, values)
        return Instruction._classify(addr, asm, size, offsets, values, result)

    @staticmethod
    def beautify(ins):
        result = ""
        if Instruction.is_arimetic(ins):
            result = " => {}".format(ins.execute())
        name = ins.name
        if Instruction.is_compare(ins):
            name = ins._strcond()
        if Instruction.is_compare(ins) and ins.signed:
            values = ", ".join("{}".format(signed(v, 8*ins.size)) for v in ins.values)
        else:
            values = ", ".join("{}".format(v) for v in ins.values)
        return f"{name} {values}{result}"


class ArithmeticIns:
    unary_ins = {
        # name: concret evaluate, symbolic evaluate
        'not': (operator.not_, operator.not_),  # 按 bits 取反
    }
    binary_ins = {
        'add': (),
        'adc': (),
        'sub': (),
        'sbb': (),
        'mul': (),
        'imul': (),
    }
    multi_ins = {
        'lea': None,
    }
    ops = {
        #'not': operator.not_,      # 按bits操作
        #'lea': None,
        #'ror': None,               # 循环右移
        #'rol': None,
        #'shr': operator.rshift,    # 逻辑右移
        #'sar': None
        #'shl': operator.lshift,
        #'sal': operator.lshift,     # 算术左移
        #'idiv': None,
        #'div': None,
        #'bswap': None,             # 按字节交换
        #'addsd': None,             # addsd xmm0, xmm1 低 64 为double浮点数运算. sd: scale double, pd: packed double
        #'subsd': None,             # 类似 addsd
        #'pcmpeqb': None,           # xmm 指令集，按照字节比较，相等置目标字节为 FF，否则为 0
        #'cmpxchg': None,
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
    }

    @staticmethod
    def contains(ins):
        return ins in ArithmeticIns.unary_ins \
                or ins in ArithmeticIns.binary_ins \
                or ins in ArithmeticIns.multi_ins

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

    def __init__(self, addr, asm, size, offsets, values):
        self.addr = addr
        self.name = asm.split()[0]
        self.asm = asm
        self.size = size
        self.offsets = offsets
        self.values = values
        self._result = None
        self._expression = None

    def execute(self):
        if self._result is not None:
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
        elif ins in ('sal', 'shl'):
            result = values[0] << values[1]
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
        elif ins in ArithmeticIns.ops:
            result = ArithmeticIns.ops[ins](values[0], values[1])
            if ins in ('pxor', 'pand', 'por'):
                debug("size: {}, ins: {}, v0: {} v1: {} rst: {}".format(self.size, self.asm, values[0], values[1], result))
        else:
            raise InstructionErr("Unspport instruction {}".format(self.asm))
        # fixed size, and convert signed to unsigned for sub, sbb
        self._result = result & ((1<<(8*self.size)) - 1)
        return self._result

    @property
    def expression(self):
        """call after symbolize()"""
        assert self._expression is not None
        return self._expression

    # 默认的 <, >, /, <<, >> 都是有符号操作，提供了 Uxx/Lxx 的操作默认都是有符号
    # 其余是无符号
    def symbolize(self, symvals):
        # remove checking
        #for sym in symvals:
        #    assert self.size*8 == sym.size()
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
        elif ins in ('sal', 'shl'):
            exp = symvals[0] << values[1]
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
            raise InstructionErr("Unspport instruction {}".format(self.asm))
        #self._expression = z3.simplify(exp)
        self._expression = exp
        return exp


class CondJumpIns:
    signed_ins = {
        'jl': COND_LT,  'jnge': COND_LT,  # <
        'js': COND_LT,                    # < 0, SF is set
        'jle': COND_LE, 'jng': COND_LE,   # <=
        'jg': COND_GT,  'jnle': COND_GT,  # >
        'jge': COND_GE, 'jnl': COND_GE,   # >=
        'jns': COND_GE,                   # >= 0, SF isnt set
    }
    unsigned_ins = {
        'jz': COND_EQ,  'je': COND_EQ,   # ==
        'jnz': COND_NE, 'jne': COND_NE,  # !=
        'jb': COND_LT,  'jnae': COND_LT, # <
        'jbe': COND_LE, 'jna': COND_LE,  # <=
        'ja': COND_GT,  'jnbe': COND_GT, # >
        'jae': COND_GE, 'jnb': COND_GE,  # >=
    }
    unspport_ins = (
        'jp',   'jnp',  # PF is set
    )

    @staticmethod
    def contains(ins_name):
        return ins_name in CondJumpIns.signed_ins \
                or ins_name in CondJumpIns.unsigned_ins \
                or ins_name in CondJumpIns.unspport_ins

    def __init__(self, addr, asm):
        self.addr = addr
        self.asm = asm
        self.name = asm.split()[0]

    @property
    def signed(self):
        if self.name in CondJumpIns.signed_ins:
            return True
        if self.name in CondJumpIns.unsigned_ins:
            return False
        if self.name in CondJumpIns.unspport_ins:
            warn("Ignore condition jump {}.".format(self.name))
            return False
        raise InstructionErr("Unspport instruction {}".format(ins))

    @property
    def condition(self):
        if self.name in CondJumpIns.signed_ins:
            return CondJumpIns.signed_ins[self.name]
        if self.name in CondJumpIns.unsigned_ins:
            return CondJumpIns.unsigned_ins[self.name]
        if self.name in CondJumpIns.unspport_ins:
            warn("Ignore condition jump {}.".format(self.name))
            return COND_UNSPPORT
        raise InstructionErr("Unspport instruction {}".format(self.asm))

    def execute(self):
        raise ValueError("Condition Jump Instruction can't execute")

    def symbolize(self):
        raise ValueError("Condition Jump Instruction can't symbolize")


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

    cmpeq_ins = ('test', 'cmpxchg')
    cmp_ins = ('cmp', 'cmpsb', 'cmpsw', 'cmpsd')

    @staticmethod
    def contains(ins):
        return ins in CompareIns.cmpeq_ins \
                or ins in CompareIns.cmp_ins

    def __init__(self, addr, asm, size, offsets, values):
        self.addr = addr
        self.asm = asm if not asm.startswith('rep') else asm[4:]    # remove 'rep ' prefix
        self.name = self.asm.split()[0]
        self.size = size
        self.offsets = offsets
        self.values = values
        self._signed = None
        self._condition = None
        self._result = None
        self._expression = None

    def _strcond(self):
        return CompareIns.conds.get(self.condition)[0]

    def setted_signed(self):
        return getattr(self, '_setted_signed', False)

    @property
    def signed(self):
        if self._signed is None:
            warn("Unknow sign, guess by operands (0x{:x}: {})".format(self.addr, self.name))
            size = 8 * self.size
            self._signed = any(guess_signed(v, size) for v in self.values)
        return self._signed

    @signed.setter
    def signed(self, signed: bool):
        """signed 只能设置一次"""
        if self.setted_signed():
            return
        self._signed = signed
        self._setted_signed = True

    def setted_condition(self):
        return getattr(self, '_setted_condition', False)

    def _guess_condition(self):
        warn("Unknow condition, guess by operands (0x{:x}: {})".format(self.addr, self.name))
        assert 2 == len(self.values)
        size = 8*self.size
        values = self.values
        v0 = signed(values[0], size) if self.signed else values[0]
        v1 = signed(values[1], size) if self.signed else values[1]
        if self.name in CompareIns.cmp_ins:
            if randint(0, 99) >= 50:
                return COND_EQ if v0 == v1 else COND_NE
            else:
                return COND_LT if v0 < v1 else \
                       COND_GT if v0 > v1 else \
                       COND_EQ
        if self.name in CompareIns.cmpeq_ins:
            return COND_EQ if v0 == v1 else COND_NE
        raise InstructionErr("Unknow compare instruction {}".format(self.asm))

    @property
    def condition(self):
        if self._condition is None or self._condition == COND_UNSPPORT:
            self._condition = self._guess_condition()
        return self._condition

    @condition.setter
    def condition(self, cond):
        """condition 只能设置一次"""
        if self.setted_condition():
            return
        self._condition = cond
        self._setted_condition = True

    def execute(self):
        if self._result is not None:
            return self._result
        assert 2 == len(self.values)
        if self.condition not in CompareIns.conds:
            raise ValueError("Unexpected condition in CompareIns")
        values = self.values
        size = 8*self.size
        v0 = signed(values[0], size) if self.signed else values[0]
        v1 = signed(values[1], size) if self.signed else values[1]
        self._result = CompareIns.conds[self.condition][1](v0, v1)
        return self._result

    @property
    def expression(self):
        assert self._expression is not None
        return self._expression

    def symbolize(self, symvals):
        assert 2 == len(symvals)
        cond = self.execute()
        if self.condition not in CompareIns.conds:
            raise ValueError("Unexpected condition in CompareIns")
        exp = CompareIns.conds[self.condition][1](symvals[0], symvals[1])
        if cond is False:
            exp = z3.Not(exp)
        self._expression = exp
        return exp


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
        warn("Unimplement JumpIns' expression()")

    def symbolize(self, symvals):
        warn("Unimplement JumpIns' symbolize()")


def previous_compare(instructions, limit=5):
    len_ = len(instructions)
    for i in range(-1, max(-limit, -len_)-1, -1):
        if Instruction.is_compare(instructions[i]):
            return len_ + i
    return NONE_ORDER


def parse_trace_file(fname):
    # 记录全部指令，以地址为记录
    instructions = []
    with open(fname, 'r') as tf:
        for trace in tf:
            ins = Instruction.from_trace(trace)
            # splited SIMD instruction
            if isinstance(ins, (tuple, list)):
                instructions.extend(ins)
            # discard condtion jump and set previous compare condition
            elif Instruction.is_condjmp(ins):
                prevcmpidx = previous_compare(instructions)
                if prevcmpidx != NONE_ORDER and not instructions[prevcmpidx].setted_condition():
                    instructions[prevcmpidx].signed = ins.signed
                    instructions[prevcmpidx].condition = ins.condition
                else:
                    warn("Discard single condtion jump. (0x{:x}: {})".format(ins.addr, ins.asm))
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
            if Instruction.is_arimetic(ins):
                result = ins.execute()
                if value == result:
                    previdx = idxes[i]
                    break
            # check operands
            opidx = find_same_operand(ins, offset, value)
            if opidx != NONE_ORDER:
                new_previdx = datagraph[idxes[i]][opidx]
                if new_previdx > previdx:
                    previdx = new_previdx
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
            # 构建指令深度图
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
        if Instruction.is_compare(ins):
            pass


def is_operand_field(offset):
    pass


def gather_magic_field(instructions):
    pass


def gather_checksum_field(instructions):
    pass


def gather_length_field(instructions):
    pass


# TODO 通过实验 hash 函数来测试此函数
def optimize_loop(instructions, cmpgraph, addr2idxes, loopinsmax=LOOPINS_MAX):
    cmpdepth = 0
    cnts = [NONE_ORDER for _ in instructions]
    for i, ins in enumerate(instructions):
        assert ins.depth is not None and ins.depth_prev is not None
        addr = ins.addr
        addrcnt = len(addr2idxes[addr])
        # 连续出现多次相同的比较指令则忽略
        if Instruction.is_compare(ins):
            if Instruction.is_splited_simd(ins):
                ins.optimized = False
                continue
            # not splited simd compare
            ins.optimized = (cmpdepth > loopinsmax)
            k = cmpgraph[i]
            cmpdepth += 1
            if k == NONE_ORDER or addr != instructions[k].addr:
                cmpdepth = 0
                # not optimized the upper bound for loop
                if k != NONE_ORDER:
                    instructions[k].optimized = False
            continue
        if addrcnt <= loopinsmax or ins.depth <= loopinsmax:
            ins.optimized = False
            continue
        # maybe need optimized
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
        ins.optimized = (cnts[i] > loopinsmax)


def build_cmpgraph(instructions):
    graph = [NONE_ORDER for _ in instructions]
    prev = NONE_ORDER
    for i, ins in enumerate(instructions):
        graph[i] = prev
        if Instruction.is_compare(ins):
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


def symbolize_value(value, offset, sign_extend=False):
    assert offset
    exp = None
    len_ = len(offset)
    for i, off in enumerate(offset):
        if off == NONE_OFFSET:
            byte = z3.BitVecVal(get_byte(value, i), 8)
        else:
            byte = z3.BitVec("b{}".format(off), 8)
            if sign_extend and i+1 < len_ and enable_sign_extend(value, offset, i):
                byte = z3.SignExt(8*(len_ - i - 1), byte)
                exp = z3.Concat(byte, exp) if exp is not None else byte
                return exp
        exp = z3.Concat(byte, exp) if exp is not None else byte
    return z3.simplify(exp)
    #return exp


def is_offset_empty(offsets):
    return not offsets or all(off == NONE_OFFSET for off in offsets)


def sort_model(model):
    rst = str(model)
    pat = r'b(\d+)\s*=\s*(\d+)'
    repls = [(int(s), int(v)) for s, v in re.findall(pat, rst)]
    repls.sort(key=operator.itemgetter(0))
    return '[' + ', '.join("b{}={}".format(s, v) for s, v in repls) + ']'


def concolic_execute(instructions, seed):
    offset2idxes = groupby_offset(instructions)
    addr2idxes = groupby_addr(instructions)
    info("buiding datagraph ...")
    datagraph = build_datagraph(instructions, offset2idxes)
    cmpgraph = build_cmpgraph(instructions)
    # 优化循环
    optimize_loop(instructions, cmpgraph, addr2idxes)
    z3.set_param(timeout=30*1000)        # 30s (unit: ms) for a solver
    #z3.set_param(max_memory=1*1024*1024*1024)  # 1G, unit: B, TODO 并没有效果，因为不支持
    ret = set()
    recent_contraint = deque(maxlen=15)
    simd_contraint = []
    for i, ins in enumerate(instructions):
        insbits = 8*ins.size
        # for every operand
        symvals = [None for _ in ins.offsets]
        for k, (offset, value) in enumerate(zip(ins.offsets, ins.values)):
            previdx = datagraph[i][k]
            symval = None
            if not is_offset_empty(offset) and not ins.optimized:
                if previdx == NONE_ORDER and is_original(value, offset, seed):
                    symval = symbolize_value(value, offset, sign_extend=True)
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

        if Instruction.is_compare(ins):
            exp = ins.symbolize(symvals) if not ins.optimized else True
            # 突破不等交给 Fuzzer，而不是 SymExe. 没有优化的指令才进行计算
            if not ins.optimized and Instruction.is_hard_compare(ins):
                info("Now begin checking compare sat, with exps:", len(recent_contraint) + len(simd_contraint) +1)
                solver = z3.Solver()
                solver.add(*recent_contraint)
                solver.add(*simd_contraint)
                solver.add(z3.Not(exp))
                rst = solver.check()
                if rst == z3.sat:
                    model = solver.model()
                    if len(model):  # TODO ignore empty answer
                        ret.add(sort_model(model))
                    debug(sort_model(model))
                elif rst == z3.unsat:
                    info("Unsat. {}: {}".format(i, Instruction.beautify(ins)))
                elif rst == z3.unknown:
                    info("Can't resolve. {}: {}".format(i, Instruction.beautify(ins)))
                else:
                    raise ValueError("Unknow result solver returned")
                if Instruction.is_splited_simd(ins):
                    simd_contraint.append(z3.Not(exp))
                else:
                    recent_contraint.append(exp)
                    simd_contraint = []
        elif Instruction.is_jump(ins):
            pass
        elif Instruction.is_arimetic(ins):
            if Instruction.is_division(ins) and not ins.optimized:
                info("Now begin checking div sat, with exps:", len(recent_contraint) + len(simd_contraint) +1)
                solver = z3.Solver()
                solver.add(*recent_contraint)
                solver.add(*simd_contraint)
                solver.add(0 == symvals[1])
                rst = solver.check()
                if rst == z3.sat:
                    model = solver.model()
                    if len(model):
                        ret.add(sort_model(model))
                    debug(sort_model(model))
                elif rst == z3.unsat:
                    info("Unsat. {}: {}".format(i, Instruction.beautify(ins)))
                elif rst == z3.unknown:
                    info("Can't resolve. {}: {}".format(i, Instruction.beautify(ins)))
                else:
                    raise ValueError("Unknow result solver returned")
            # symbolize this expression
            ins.symbolize(symvals)
        else:
            raise InstructionErr("Unspport instruction {}".format(ins.asm))

    return list(ret)


def print_instruction(instructions):
    pass


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
        name = ','.join("b{}={:02x}".format(s, v) for s, v in repls)
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


def disabled_aslr():
    v = subprocess.check_output(['sysctl', '-n', 'kernel.randomize_va_space'])
    return b'0' == v.strip()


def main():
    if len(sys.argv) > 1 and not any(h in sys.argv for h in ('-h', '--help', '-?')):
        if not disabled_aslr():
            print("Please disable ASLR via: sysctl kernel.randomize_va_space=0")
            return 104

    args = parser.parse_args()

    if args.quiet:
        global be_quiet
        be_quiet = True

    # server mode
    if args.server_mode:
        server_mode()
        return 0

    # plot data graph from trace file
    if args.dot_file and args.trace_file:
        instructions = parse_trace_file(args.trace_file)
        offset2idxes = groupby_offset(instructions)
        datagraph = build_datagraph(instructions, offset2idxes)
        plot_datagraph(instructions, datagraph, args.dot_file)
        return 0

    if not args.seed_file:
        parser.print_usage()
        return 101

    # trace file + concolic execution
    if args.trace_file:
        if args.detect_struct:
            pass
        else:
            seed = readfile(args.seed_file)
            instructions = parse_trace_file(args.trace_file)
            result = concolic_execute(instructions, seed)
        return 0

    # taint + concolic execution
    if args.output_dir and args.cmd:
        if not leetaint(args.seed_file, args.output_dir, args.cmd):
            print("leetaint fails")
            return 102
        trace_file = os.path.join(args.output_dir, 'trace.txt')
        seed = readfile(args.seed_file)
        testcasepath = os.path.join(args.output_dir, 'testcases')
        instructions = parse_trace_file(trace_file)
        result = concolic_execute(instructions, seed)
        saved_files = save_all_testcases(result, seed, testcasepath)
        return 0

    # invalid useage
    parser.print_usage()
    return 103


if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
