#include <algorithm>
#include <iostream>

#include "instrument.hh"
#include "trace.hh"

using namespace std;

ofstream trace;

void dump_reg_offset(REG reg, UINT32 size)
{
    // trick for, shl eax, cl 这类指令
    size = min(size, REG_Size(reg));
    trace << "{";
    if (isRegisterTainted(reg)) {
        UINT64 const* offset = getRegisterOffset(reg);
        for (UINT64 i = 0; i < size; i++) {
            if (isRegisterOffsetTainted(reg, i))
                trace << "0x" << std::hex << offset[i];
            trace << ",";
        }
    }
    trace << "}";
}

void dump_mem_offset(ADDRINT addr, UINT32 size)
{
    Byte* b;
    trace << "{";
    for (UINT32 i = 0; i < size; ++i) {
        b = getTaintByte(addr + i);
        if (b) {
            trace << "0x" << std::hex << b->offset;
        }
        trace << ",";
    }
    trace << "}";
}

//print value
void dump_value(UINT64 val, UINT32 size)
{
    UINT8 const* bytes = (UINT8 const*)&val;
    for (UINT32 c = 0; c < size; c++)
        trace << setw(2) << setfill('0') << std::hex << int(bytes[c]);
}

void dump_addr(UINT8 const* addr, UINT32 size)
{
    for (UINT32 c = 0; c < size; c++)
        trace << setw(2) << setfill('0') << std::hex << int(addr[c]);
}

//trace reg
void tracelog_reg(UINT64 insAddr, string const& insDis, REG reg, UINT64 val, UINT32 size)
{
    size = min(size, REG_Size(reg));
    // 0xabcd.{0x0,0x1,}.ffff.
    trace << hex << "0x" << insAddr << "." << insDis << ".";
    dump_reg_offset(reg, size);
    trace << ".";
    dump_value(val, size);
    trace << "." << endl;
}

//trace reg imm
void tracelog_regimm(UINT64 insAddr, string const& insDis, REG reg, UINT64 val, UINT64 imm, UINT32 size)
{
    UINT32 regsize = min(size, REG_Size(reg));
    // 0xabcd.{0x0,0x1,}.aaaa.ffff.
    trace << hex << "0x" << insAddr << "." << insDis << ".";
    dump_reg_offset(reg, regsize);
    trace << ".";

    dump_value(val, regsize);
    trace << ".";

    dump_value(imm, size);
    trace << "." << endl;
}

//trace reg reg
void tracelog_regreg(UINT64 insAddr, string const& insDis, REG reg1, UINT64 val1, REG reg2, UINT64 val2, UINT32 size)
{
    UINT32 r1size = min(size, REG_Size(reg1));
    UINT32 r2size = min(size, REG_Size(reg2));
    // 0xabcd.{0x0,0x1,}.{0x3,0x4}.aaaa.ffff.
    trace << hex << "0x" << insAddr << "." << insDis << ".";
    dump_reg_offset(reg1, r1size);
    dump_reg_offset(reg2, r2size);
    trace << ".";

    dump_value(val1, r1size);
    trace << ".";

    dump_value(val2, r2size);
    trace << "." << endl;
}

//trace reg reg imm
void tracelog_regregimm(UINT64 insAddr, string const& insDis, REG reg1, UINT64 val1, REG reg2, UINT64 val2, UINT64 imm, UINT32 size)
{
    UINT32 r1size = min(size, REG_Size(reg1));
    UINT32 r2size = min(size, REG_Size(reg2));

    trace << hex << "0x" << insAddr << "." << insDis << ".";
    dump_reg_offset(reg1, r1size);
    dump_reg_offset(reg2, r2size);
    trace << ".";

    dump_value(val1, r1size);
    trace << ".";

    dump_value(val2, r2size);
    trace << ".";

    dump_value(imm, size);
    trace << "." << endl;
}

//trace reg mem imm
void tracelog_regmemimm(UINT64 insAddr, string const& insDis, REG reg, UINT64 val1, ADDRINT addr, UINT64 val2, UINT64 imm, UINT32 size)
{
    UINT32 regsize = min(size, REG_Size(reg));
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    dump_reg_offset(reg, regsize);
    dump_mem_offset(addr, size);
    trace << ".";

    dump_value(val1, regsize);
    trace << ".";

    dump_value(val2, size);
    trace << ".";

    dump_value(imm, size);
    trace << "." << endl;
}

//trace reg mem
void tracelog_regmem(UINT64 insAddr, string const& insDis, REG reg, UINT64 val1, ADDRINT addr, INT64 val2, UINT32 size)
{
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    dump_reg_offset(reg, size);
    dump_mem_offset(addr, size);
    trace << ".";

    dump_value(val1, size);
    trace << ".";

    dump_value(val2, size);
    trace << "." << endl;
}

//trace mem reg
void tracelog_memreg(UINT64 insAddr, string const& insDis, ADDRINT addr, INT64 val1, REG reg, UINT64 val2, UINT32 size)
{
    UINT32 regsize = min(size, REG_Size(reg));
    trace << hex << "0x" << insAddr << "." << insDis << ".";

    dump_mem_offset(addr, size);
    dump_reg_offset(reg, regsize);
    trace << ".";

    dump_value(val1, size);
    trace << ".";

    dump_value(val2, regsize);
    trace << "." << endl;
}

//trace mem mem
void tracelog_memmem(UINT64 insAddr, string const& insDis, ADDRINT addr1, INT64 val1, ADDRINT addr2, INT64 val2, UINT32 size)
{
    trace << hex << "0x" << insAddr << "." << insDis << ".";
    dump_mem_offset(addr1, size);
    dump_mem_offset(addr2, size);
    trace << ".";

    dump_value(val1, size);
    trace << ".";
    dump_value(val2, size);
    trace << "." << endl;
}

// trace mem mem via addr
void tracelog_memmem_addr(UINT64 insaddr, string const& disasm, ADDRINT addr1, ADDRINT addr2, UINT32 size)
{
    trace << hex << "0x" << insaddr << "." << disasm << ".";
    dump_mem_offset(addr1, size);
    dump_mem_offset(addr2, size);
    trace << ".";

    dump_addr((UINT8*)addr1, size);
    trace <<  ".";
    dump_addr((UINT8*)addr2, size);
    trace << "." << endl;
}

//trace mem
void tracelog_mem(UINT64 insAddr, string const& insDis, ADDRINT addr, INT64 val, UINT32 size)
{
    trace << hex << "0x" << insAddr << "." << insDis << ".";
    dump_mem_offset(addr, size);
    trace << ".";

    dump_value(val, size);
    trace << "." << endl;
}

//trace mem imm
void tracelog_memimm(UINT64 insAddr, string const& insDis, ADDRINT addr, INT64 val, UINT64 imm, UINT32 size)
{
    trace << hex << "0x" << insAddr << "." << insDis << ".";
    dump_mem_offset(addr, size);
    trace << ".";

    dump_value(val, size);
    trace << ".";

    dump_value(imm, size);
    trace << "." << endl;
}

void tracelog_leamem(UINT64 insaddr, string const& insdis,
        REG base, UINT64 bval,
        UINT32 scale,
        REG idx, UINT64 ival,
        UINT64 disp,
        UINT32 size)
{
    // addr.lea ecx, [eax+4*ebx+0x22].{base offsets}.{idx offsets}.bval.ival.scale.disp.
    UINT32 bsize = size;
    UINT32 isize = size;
    trace << hex << "0x" << insaddr << "." << insdis << ".";
    if (REG_valid(base)) {
        bsize = min(size, REG_Size(base));
        dump_reg_offset(base, bsize);
    } else {
        trace << "{}";
    }
    trace << ".";
    if (REG_valid(idx)) {
        isize = min(size, REG_Size(idx));
        dump_reg_offset(idx, isize);
    } else {
        trace << "{}";
    }
    trace << ".";
    dump_value(bval, bsize);
    trace << ".";
    dump_value(ival, isize);
    trace << ".";
    dump_value(scale, size);
    trace << ".";
    dump_value(disp, isize);
    trace << "." << endl;
}

void tracelog_jmpreg(UINT64 insaddr, string const& insdis, ADDRINT result, REG reg, UINT64 val, UINT32 size)
{
    // addr.jmp eax.result.{offsets}.val.
    size = min(size, REG_Size(reg));
    trace << hex << "0x" << insaddr << "." << insdis << ".";
    dump_value(result, size);
    trace << ".";
    dump_reg_offset(reg, size);
    trace << ".";
    dump_value(val, size);
    trace << "." << endl;
}

void tracelog_jmpmem(UINT64 insaddr, string const& insdis, ADDRINT result,
        REG base, UINT64 bval,
        UINT32 scale,
        REG idx, UINT64 ival,
        UINT64 disp,
        UINT32 size)
{
    // addr.jmp [eax+4*ebx+0x22].result.{base offsets}.{idx offsets}.bval.ival.scale.disp.
    UINT32 bsize = size;
    UINT32 isize = size;
    trace << hex << "0x" << insaddr << "." << insdis << ".";
    dump_value(result, size);
    trace << ".";
    if (REG_valid(base)) {
        bsize = min(size, REG_Size(base));
        dump_reg_offset(base, bsize);
    } else {
        trace << "{}";
    }
    trace << ".";
    if (REG_valid(idx)) {
        isize = min(size, REG_Size(idx));
        dump_reg_offset(idx, isize);
    } else {
        trace << "{}";
    }
    trace << ".";
    dump_value(bval, bsize);
    trace << ".";
    dump_value(ival, isize);
    trace << ".";
    dump_value(scale, size);
    trace << ".";
    dump_value(disp, isize);
    trace << "." << endl;
}

void tracelog_ins(UINT64 insaddr, string const& insdis)
{
    trace << hex << "0x" << insaddr << "." << insdis << ".";
    trace << endl;
}

#if 0
//trace reg reg SIMD
// TODO 什么是 reg mem SIMD
void tracelog_regreg(UINT64 insAddr, string const& insDis, REG reg1, INT64 val1, REG reg2, INT64 val2, UINT32 size)
{
    trace << hex << "0x" << insAddr << "." << insDis << ".";
    dump_reg_offset(reg1, size);
    dump_reg_offset(reg2, size);
    trace << ".";

    dump_value(val1, size);
    trace << ".";
    dump_value(val2, size);
    trace << "." << endl;
}

//trace reg mem SIMD
// TODO 什么是 reg mem SIMD
void tracelog_regmem(UINT64 insAddr, string const& insDis, REG reg, INT64 val1, ADDRINT addr, INT64 val2, UINT32 size)
{
    trace << hex << "0x" << insAddr << "." << insDis << ".";
    dump_reg_offset(reg, size);
    dump_mem_offset(addr, size);
    trace << ".";

    dump_value(val1, size);
    trace << ".";
    dump_value(val2, size);
    trace << "." << endl;
}
#endif
