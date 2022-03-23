#include <iostream>
#include <list>
#include <string>
#include <algorithm>

#include "instruction.hh"
#include "instrument.hh"
#include "trace.hh"
#include "common.h" // import BUG_ON

using namespace std;

bool cmp_tainted = false;

static inline
UINT64 read_uint(UINT8 const* addr, UINT32 size)
{
    BUG_ON(!IS_POWER_OF2(size));
    switch (size) {
    case 1: return *addr;
    case 2: return *(UINT16 const*)addr;
    case 4: return *(UINT32 const*)addr;
    case 8: return *(UINT64 const*)addr;
    default:
            printf("%p: size: %d\n", addr, size);
            UNREACHABLE(); // Not supoort now
    }
}

static inline
UINT64 get_reg_value(CONTEXT* ctx, REG reg)
{
    UINT64 ret;
    PIN_GetContextRegval(ctx, reg, (UINT8*)&ret);
    return ret;
}

void initMemTaint(MemBlock* map, ADDRINT addr, UINT32 size)
{
    BUG_ON(!map);
    BUG_ON(!IS_ERG_SIZE(size));

    map->tainted = 0x0;

    for (UINT32 i = 0; i < REGISTER_WIDTH; ++i)
        map->offset[i] = INVALID_OFFSET;

    for (UINT32 i = 0; i < size; i++){
        Byte* b = getTaintByte(addr + i);
        if (b) {
            set_bitmap(map->tainted, i);
            map->offset[i] = b->offset;
        }
    }
}

void initMemTaint(MemBlock* map1, ADDRINT addr1, MemBlock* map2, ADDRINT addr2, UINT32 size, UINT32 count)
{
    initMemTaint(map1, addr1, size * count);
    initMemTaint(map1, addr1, size * count);
}

void traceUnsupport(ADDRINT insAddr, std::string insDis){
    logfile << "[Unsupport]" << " insDis: " << insDis << endl;
}

VOID taintMOVS(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT memOp1, UINT32 readSize, ADDRINT memOp2, UINT32 writeSize)
{
    list<Byte*>::iterator i;
    UINT64 readAddr = memOp1;
    UINT64 writeAddr = memOp2;

    if (opCount < 2) {
        return;
    }

    for (UINT64 i = 0; i < writeSize; i++){
        bool isReadMemTainted = isByteTainted(readAddr+i);
        bool isWriteMemTainted = isByteTainted(writeAddr+i);

        Byte* tempMem = getTaintByte(readAddr + i);

        // if read mem tainted -> taint write mem
        if(isReadMemTainted){
            addTaintByte(writeAddr+i, tempMem->offset);
        }
        // if read mem not tainted && write mem tainted -> free memory
        else if(isWriteMemTainted){
            removeTaintByte(writeAddr+i);
        }
        // if read mem not tainted && write mem not tainted -> do nothing
        else {
        }
    }
}

void taintRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG src, REG dst, ADDRINT val, UINT32 size)
{
    // TODO 处理 mov eax, eax 这类会符号扩展到 rax 高位的情况, clear 高位
    BUG_ON(size > REG_Size(dst));

    if (src == dst) {
#ifdef DEBUG
        tracelog_regreg(insAddr, insDis, src, 0xcccc, dst, val, size);
#endif
        return;
    }

    if (isRegisterTainted(src))
        taintRegister(dst, getRegisterOffset(src), size);
    else
        clearRegister(dst, size);
}

VOID taintRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, UINT32 size)
{
    BUG_ON(size > REG_Size(reg));
#ifdef DEBUG
    if (isRegisterTainted(reg))
        tracelog_regimm(insAddr, insDis, reg, 0xcccc, 0xcccc, size);
#endif
    clearRegister(reg, size);
}

VOID taintMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, ADDRINT val, UINT32 size)
{
    BUG_ON(size > REG_Size(reg));

    if (!isRegisterTainted(reg)) {
        for (UINT32 i = 0; i < size; ++i)
            removeTaintByte(addr + i);
        return;
    }

    UINT64 const* offset = getRegisterOffset(reg);
    for (UINT32 i = 0; i < size; ++i) {
        if (isRegisterOffsetTainted(reg, i))
            addTaintByte(addr + i, offset[i]);
        else
            removeTaintByte(addr + i);
    }
 }

VOID taintRegMem(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, UINT32 size)
{
    BUG_ON(size > REG_Size(reg));
    BUG_ON(size > REGISTER_WIDTH);

    UINT64 offset[REGISTER_WIDTH];
    Byte* b;
    for (UINT64 i = 0; i < size; ++i) {
        offset[i] = INVALID_OFFSET;
        b = getTaintByte(addr + i);
        if (b)
            offset[i] = b->offset;
    }
    //if (0 == strncmp(insDis.c_str(), "movdqa", 6)) {
    //    UINT8 regval[REGISTER_WIDTH] = "";
    //    tracelog_regmem(insAddr, insDis, reg, regval, addr, (UINT8*)addr, size);
    //}
    taintRegister(reg, offset, size);
}

VOID taintMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size)
{
    BUG_ON(!IS_POWER_OF2(size));
    BUG_ON(size > REGISTER_WIDTH);

#ifdef DEBUG
    MemBlock block;
    initMemTaint(&block, addr, size);
    if (block.tainted) {
        UINT64 memval = read_uint((UINT8*)addr, size);
        tracelog_memimm(insAddr, insDis, addr, memval, 0xcccc, size);
    }
#endif

    for (UINT32 i = 0; i < size; i++)
        removeTaintByte(addr+i);
}

VOID taintMemMem(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT readAddr, UINT32 readSize, ADDRINT writeAddr, UINT32 writeSize)
{
    BUG_ON(readSize != writeSize);

    // TODO 处理内存区间重叠的情况
    BUG_ON(readAddr < writeAddr && writeAddr < readAddr + readSize);

    if (readAddr == writeAddr)
        return;

    Byte* src;
    for (UINT32 i = 0; i < writeSize; i++){
        src = getTaintByte(readAddr + i);
        if (src) {
            addTaintByte(writeAddr + i, src->offset);
        } else {
            removeTaintByte(writeAddr + i);
        }
    }
}

void taintSTOS(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT memOp, UINT32 writeSize)
{
    REG reg;
    UINT64 addr = memOp;

    switch (writeSize) {
#if defined(TARGET_IA32E)
    case REG_SIZE_8:
        reg = REG_RAX;
        break;
#endif
    case REG_SIZE_4:
        reg = REG_EAX;
        break;
    case REG_SIZE_2:
        reg = REG_AX;
        break;
    case REG_SIZE_1:
        reg = REG_AL;
        break;
    default:
        UNREACHABLE(); // error
    }

    UINT64 const* offset = getRegisterOffset(reg);
    for (UINT64 i = 0; i < writeSize; i++){
        bool isMemTainted = isByteTainted(addr+i);
        bool isRegOffsetTainted = isRegisterOffsetTainted(reg, i);

        // if reg offset not tainted && mem tainted  -> free memory
        if (!isRegOffsetTainted && isMemTainted) {
            removeTaintByte(addr+i);
        }
        // if reg offset tainted && mem not tainted -> taint memory
        else if (isRegOffsetTainted && !isMemTainted) {
            addTaintByte(addr+i, offset[i]);
        } 
        // if reg offset tainted && mem tainted     -> update taint offset
        else if (isRegOffsetTainted && isMemTainted) {
            //removeTaintByte(addr+i);
            addTaintByte(addr+i, offset[i]);
        }
        // if reg offset not tainted && mem not tainted -> nothing
        else if(!isRegOffsetTainted && !isMemTainted){

        }
    }
}

VOID taintLODS(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 rdsize)
{
    REG reg;
    switch (rdsize) {
#if defined(TARGET_IA32E)
    case REG_SIZE_8:
        reg = REG_RAX;
        break;
#endif
    case REG_SIZE_4:
        reg = REG_EAX;
        break;
    case REG_SIZE_2:
        reg = REG_AX;
        break;
    case REG_SIZE_1:
        reg = REG_AL;
        break;
    default:
        UNREACHABLE(); //error
    }

    UINT64 offset[REGISTER_WIDTH];

    Byte* b;
    for (UINT64 i = 0; i < rdsize; i++){
        b = getTaintByte(addr + i);
        if (b)
            offset[i] = b->offset;
    }

    taintRegister(reg, offset, rdsize);
}

VOID taintLEA(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, UINT32 size)
{
    clearRegister(reg, size);
}

/**
 * lea ecx, [eax+4*ebx+0x4242]
 * base: eax
 * idx: ebx
 * dst: ecx
 */
VOID taint_lea_mem(ADDRINT addr, string const& disasm, CONTEXT* ctx,
        REG dst, REG base, REG idx, UINT32 scale, UINT64 disp, UINT32 inssize, UINT32 size)
{
    UINT64 bval = 0, ival = 0;
    if (REG_valid(base)) {
        bval = get_reg_value(ctx, base);
        if (REG_RIP == base || REG_EIP == base || REG_IP == base)
            bval += inssize;
    }
    if (REG_valid(idx))
        ival = get_reg_value(ctx, idx);

    BUG_ON(!IS_POWER_OF2(scale));
    BUG_ON(size > REGISTER_WIDTH);

    // idx 优先级大于 base, idx 更有价值
    if (REG_valid(idx)) {
        UINT64 const* offset = getRegisterOffset(idx);
        if (isRegisterTainted(idx)) {
            // TODO lea edx, ptr [rcx-0x1], 指令处理不合理
            // rcx-0x1 按照 64 位处理，然后截取低32位给 edx,
            // 这里不处理把，后续再分析中处理 {,,,,} 的问题
            tracelog_leamem(addr, disasm, base, bval, scale, idx, ival, disp, size);
            taintRegister(dst, offset, size);
            return;
        }
    }

    if (REG_valid(base)) {
        UINT64 const* offset = getRegisterOffset(base);
        if (isRegisterTainted(base)) {
            tracelog_leamem(addr, disasm, base, bval, scale, idx, ival, disp, size);
            taintRegister(dst, offset, size);
            return;
        }
    }
    // 寄存器未被污染信息，直接清除
    clearRegister(dst, size);
}

VOID traceCMPRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    if (isRegisterTainted(reg1) || isRegisterTainted(reg2)) {
        cmp_tainted = true;
        // test rax, rax ==> cmp rax, 0x0
        if (reg1 == reg2 && (0 == strncmp(insDis.c_str(), "test", 4))) {
            tracelog_regimm(insAddr, insDis, reg1, val1, 0x0, size);
        } else {
            tracelog_regreg(insAddr, insDis, reg1, val1, reg2, val2, size);
        }
    }
}

void trace_vpcmp_rrr(ADDRINT insaddr, string const& disasm, CONTEXT* ctx, REG dst, REG src1, REG src2)
{
    BUG_ON(REG_Size(src1) != REG_Size(src2));
    UINT32 regsize = REG_Size(src1);
    if (isRegisterTainted(src1) || isRegisterTainted(src2)) {
        UINT8 src1val[REGISTER_WIDTH], src2val[REGISTER_WIDTH];
        PIN_GetContextRegval(ctx, src1, src1val);
        PIN_GetContextRegval(ctx, src2, src2val);
        tracelog_regreg(insaddr, disasm, src1, src1val, src2, src2val, regsize);
    }
    clearRegister(dst, REG_Size(dst));
}

void trace_vpcmp_rrm(ADDRINT insaddr, string const& disasm, CONTEXT* ctx, REG dst, REG src1, ADDRINT addr, UINT32 memsize)
{
    MemBlock mem;
    initMemTaint(&mem, addr, memsize);
    if (isRegisterTainted(src1) || mem.tainted) {
        UINT8 srcval[REGISTER_WIDTH];
        PIN_GetContextRegval(ctx, src1, srcval);
        tracelog_regmem(insaddr, disasm, src1, srcval, addr, (UINT8*)addr, memsize);
    }
    clearRegister(dst, REG_Size(dst));
}

VOID tracePCMPRegReg(ADDRINT insAddr, string insDis, CONTEXT* ctx, UINT32 opCount, REG reg1, REG reg2, UINT32 size)
{
    BUG_ON(REG_Size(reg1) != size);
    BUG_ON(REG_Size(reg1) > 64);
    BUG_ON(REG_Size(reg2) > 64);

    UINT8 val1[REGISTER_WIDTH], val2[REGISTER_WIDTH];
    PIN_GetContextRegval(ctx, reg1, val1);
    PIN_GetContextRegval(ctx, reg2, val2);

    if (isRegisterTainted(reg1) || isRegisterTainted(reg2))
        tracelog_regreg(insAddr, insDis, reg1, val1, reg2, val2, size);
}

VOID tracePCMPRegMem(ADDRINT insAddr, string insDis, CONTEXT* ctx, UINT32 opCount, REG reg, ADDRINT addr, UINT32 size)
{
    BUG_ON(REG_Size(reg) > 64);
    BUG_ON(size > REGISTER_WIDTH);

    UINT8 regval[REGISTER_WIDTH];
    PIN_GetContextRegval(ctx, reg, regval);
    MemBlock mem;
    initMemTaint(&mem, addr, size);

    if (isRegisterTainted(reg) || mem.tainted)
        tracelog_regmem(insAddr, insDis, reg, regval, addr, (UINT8*)addr, size);
}


VOID traceCMPRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, UINT32 size, UINT64 imm)
{
    if (isRegisterTainted(reg)) {
        cmp_tainted = true;
        tracelog_regimm(insAddr, insDis, reg, val, imm, size);
    }
}

VOID traceCMPRegMem(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, ADDRINT addr, UINT32 size)
{
    BUG_ON(size > REGISTER_WIDTH);
    BUG_ON(size > REG_Size(reg));

    MemBlock mem;
    initMemTaint(&mem, addr, size);

    if (isRegisterTainted(reg) || mem.tainted) {
        cmp_tainted = true;
        UINT64 memval = read_uint((UINT8*)addr, size);
        tracelog_regmem(insAddr, insDis, reg, val, addr, memval, size);
    }
}

VOID traceCMPMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, ADDRINT val, UINT32 size)
{
    BUG_ON(size > REG_Size(reg));
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    if (isRegisterTainted(reg) || mem.tainted) {
        cmp_tainted = true;
        UINT64 memval = read_uint((UINT8*)addr, size);
        tracelog_memreg(insAddr, insDis, addr, memval, reg, memval, size);
    }
}

VOID traceCMPMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);

    if (mem.tainted) {
        cmp_tainted = true;
        UINT64 memval = read_uint((UINT8*)addr, size);
        tracelog_memimm(insAddr, insDis, addr, memval, imm, size);
    }
}

VOID traceCMPS(ADDRINT insAddr, string insDis, UINT32 opCount, BOOL isFirst , ADDRINT addr1, ADDRINT addr2, UINT32 size, UINT32 count)
{
    if (!isFirst)
        return;

    MemBlock mem1;
    MemBlock mem2;
    initMemTaint(&mem1, addr1, &mem2, addr2, size, count);

    if (mem1.tainted || mem2.tainted) {
        cmp_tainted = true;
        tracelog_memmem_addr(insAddr, insDis, addr1, addr2, size * count);
    }
}

VOID traceArithRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    UINT64 offset[REGISTER_WIDTH];

    if (isRegisterTainted(reg1)) {
        tracelog_regreg(insAddr, insDis, reg1, val1, reg2, val2, size);
        // reg1, reg2 both tainted
        if (isRegisterTainted(reg2)) {
            UINT64 const* off1 = getRegisterOffset(reg1);
            UINT64 const* off2 = getRegisterOffset(reg2);
            for (UINT32 i = 0; i < size; i++) {
                offset[i] = off1[i];
                if (!isRegisterOffsetTainted(reg1, i) && isRegisterOffsetTainted(reg2, i))
                    offset[i] = off2[i];
            }
            taintRegister(reg1, offset, size);
        }
        // reg1 tainted, only, do nothing
    }
    // reg2 tainted, only
    else if (isRegisterTainted(reg2)) {
        tracelog_regreg(insAddr, insDis, reg1, val1, reg2, val2, size);
        taintRegister(reg1, getRegisterOffset(reg2), size);
    }
}

VOID traceXORRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    // xor eax, eax <==> mov eax, 0x0
    // pxor xmm0, xmm0 <==> mov xmm0, 0x0
    if (reg1 == reg2) {
        clearRegister(reg1, size);
        return;
    }

    traceArithRegReg(insAddr, insDis, opCount, reg1, val1, reg2, val2, size);
}

VOID traceArithRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, UINT32 size, UINT64 imm)
{
    if (isRegisterTainted(reg))
        tracelog_regimm(insAddr, insDis, reg, val, imm, size);
}

VOID traceArithReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, UINT32 size)
{
    if (isRegisterTainted(reg))
        tracelog_reg(insAddr, insDis, reg, val, size);
}

VOID traceArithMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, ADDRINT val, UINT32 size)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    // mem is tainted
    if (mem.tainted) {
        tracelog_memreg(insAddr, insDis, addr, memval, reg, val, size);

        UINT64 const* offreg = getRegisterOffset(reg);
        for (UINT32 i = 0; i < size; ++i) {
            if (!get_bitmap(mem.tainted, i) && isRegisterOffsetTainted(reg, i) && offreg)
                addTaintByte(addr + i, offreg[i]);
        }
    }
    // reg is tainted, only
    else if (isRegisterTainted(reg)) {
        tracelog_memreg(insAddr, insDis, addr, memval, reg, val, size);
        addTaintBlock(addr, getRegisterOffset(reg), size);
    }
}

VOID traceArithRegMem(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, ADDRINT addr, UINT32 size)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    // reg is tainted
    if (isRegisterTainted(reg)) {
        tracelog_regmem(insAddr, insDis, reg, val, addr, memval, size);

        UINT64 offset[REGISTER_WIDTH];
        for (UINT32 i = 0; i < size; i++){
            offset[i] = INVALID_OFFSET;
            if (!isRegisterOffsetTainted(reg, i) && get_bitmap(mem.tainted, i))
                offset[i] = mem.offset[i];
        }
        taintRegister(reg, offset, size);
    }
    // mem is tainted, only
    else if (mem.tainted) {
        tracelog_regmem(insAddr, insDis, reg, val, addr, memval, size);
        taintRegister(reg, mem.offset, size);
    }
}

VOID traceArithMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock map;
    initMemTaint(&map, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    if (map.tainted)
        tracelog_memimm(insAddr, insDis, addr, memval, imm, size);
}

VOID traceArithMem(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock map;
    initMemTaint(&map, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    if (map.tainted)
        tracelog_mem(insAddr, insDis, addr, memval, size);
}

/**
 * and eax, 0x01
 */
VOID traceANDRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, UINT32 size, UINT64 imm)
{
    if (isRegisterTainted(reg)) {
        tracelog_regimm(insAddr, insDis, reg, val, imm, size);

        UINT64 offset[REGISTER_WIDTH];
        UINT64 const* offreg = getRegisterOffset(reg);
        for (UINT32 i = 0; i < size; i++) {
            UINT8 byte = (imm >> (i*8)) & 0xff;
            offset[i] = offreg[i];
            if (byte == 0)
                offset[i] = INVALID_OFFSET;
        }
        taintRegister(reg, offset, size);
    }
}

/**
 * and [eax+0x2], 0x42
 */
VOID traceANDMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock map;
    initMemTaint(&map, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    if (map.tainted) {
        tracelog_memimm(insAddr, insDis, addr, memval, imm, size);
        for (UINT32 i = 0; i < size; ++i) {
            UINT8 byte = (imm >> (i*8)) & 0xff;
            if (byte == 0)
                removeTaintByte(addr + i);
        }
    }
}

/**
 * or eax, eax
 */
VOID traceORRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    traceArithRegReg(insAddr, insDis, opCount, reg1, val1, reg2, val2, size);
}

/**
 * or [eax+0x], ebx
 */
VOID traceORMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, ADDRINT val, UINT32 size)
{
    traceArithMemReg(insAddr, insDis, opCount, addr, reg, val, size);
}

static inline
void copy_offset(UINT64* dst, UINT64 const* src, UINT32 size)
{
    memcpy(dst, src, size * sizeof(UINT64));
}

static
void shl_reg(REG reg, UINT32 shift, UINT32 size)
{
    BUG_ON(size == 0);
    BUG_ON(size > REGISTER_WIDTH);
    BUG_ON(!isRegisterTainted(reg));
    // 非字节偏移，认为没有操作，同样依赖完整输入
    if (shift%8 != 0)
        return;
    // 按照字节的移位
    UINT64 offset[REGISTER_WIDTH];
    UINT64 const* offreg = getRegisterOffset(reg);
    copy_offset(offset, offreg, size);

    shift = (shift/8) + ((shift%8) >= 4);
    shift = min(size, shift);
    for (INT32 i = size-1; i >= (INT32)shift; --i)
        offset[i] = offset[i - shift];
    for (INT32 i = shift-1; i >= 0; --i)
        offset[i] = INVALID_OFFSET;
    taintRegister(reg, offset, size);
}

static
void shl_mem(ADDRINT addr, MemBlock* mem, UINT32 shift, UINT32 size)
{
    BUG_ON(size == 0);
    BUG_ON(size > REGISTER_WIDTH);
    if (shift%8 != 0)
        return;
    // 按照字节的移位
    UINT64* offset = mem->offset;
    shift = (shift/8) + ((shift%8) >= 4);
    shift = min(size, shift);
    for (INT32 i = size-1; i >= (INT32)shift; --i)
        offset[i] = offset[i - shift];
    for (INT32 i = shift-1; i >= 0; --i)
        offset[i] = INVALID_OFFSET;
    addTaintBlock(addr, offset, size);
}


/**
 * shl reg, 0x2
 */
VOID traceSHLRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, UINT32 size, UINT64 imm)
{
    if (isRegisterTainted(reg)) {
        tracelog_regimm(insAddr, insDis, reg, val, imm, size);

        shl_reg(reg, imm, size);
    }
}

/**
 * shl eax, ebx
 */
VOID traceSHLRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    if (isRegisterTainted(reg1)) {
        tracelog_regreg(insAddr, insDis, reg1, val1, reg2, val2, size);

        shl_reg(reg1, val2, size);
    }
}

/**
 * shl [eax+0x1], ebx
 */
VOID traceSHLMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, ADDRINT val, UINT32 size)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    if (mem.tainted) {
        tracelog_memreg(insAddr, insDis, addr, memval, reg, val, size);

        shl_mem(addr, &mem, val, size);
    }
}

/**
 * shl [eax+0x], 0x4
 */
VOID traceSHLMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    if (mem.tainted) {
        tracelog_memimm(insAddr, insDis, addr, memval, imm, size);
        shl_mem(addr, &mem, imm, size);
    }
}

static
void shr_reg(REG reg, UINT32 shift, UINT32 size)
{
    BUG_ON(!isRegisterTainted(reg));
    if (shift%8 != 0)
        return;
    // 按照字节的移位
    UINT64 offset[REGISTER_WIDTH];
    UINT64 const* offreg = getRegisterOffset(reg);
    copy_offset(offset, offreg, size);

    shift = (shift/8) + ((shift%8) >= 4);
    shift = min(size, shift);
    for (UINT32 i = 0; i < size - shift; ++i)
        offset[i] = offset[i+shift];
    for (UINT32 i = size - shift; i < size; ++i)
        offset[i] = INVALID_OFFSET;
    taintRegister(reg, offset, size);
}

static
void shr_mem(ADDRINT addr, MemBlock* mem, UINT32 shift, UINT32 size)
{
    if (shift%8 != 0)
        return;
    UINT64* offset = mem->offset;
    shift = (shift/8) + ((shift%8) >= 4);
    shift = min(size, shift);
    for (UINT32 i = 0; i < size - shift; ++i)
        offset[i] = offset[i+shift];
    for (UINT32 i = size - shift; i < size; ++i)
        offset[i] = INVALID_OFFSET;
    addTaintBlock(addr, offset, size);
}

/**
 * shr eax, 0x4
 */
VOID traceSHRRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, UINT32 size, UINT64 imm)
{
    if (isRegisterTainted(reg)) {
        tracelog_regimm(insAddr, insDis, reg, val, imm, size);

        shr_reg(reg, imm, size);
    }
}

/**
 * shr eax, ebx
 */
VOID traceSHRRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    if (isRegisterTainted(reg1)) {
        tracelog_regreg(insAddr, insDis, reg1, val1, reg2, val2, size);

        shr_reg(reg1, val2, size);
    }
}

/**
 * shr [eax+0x2], ebx
 */
VOID traceSHRMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, ADDRINT val, UINT32 size)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    if (mem.tainted) {
        tracelog_memreg(insAddr, insDis, addr, memval, reg, val, size);
        shr_mem(addr, &mem, val, size);
    }
}

/**
 * shr [eax+0x2], 0x4
 */
VOID traceSHRMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, UINT32 size, UINT64 imm)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    if (mem.tainted) {
        tracelog_memimm(insAddr, insDis, addr, memval, imm, size);
        shr_mem(addr, &mem, imm, size);
    }
}

/**
 * mul reg1, reg2, imm ==> reg1 = reg2 * imm
 */
VOID traceMULRegRegImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size, UINT64 imm)
{
    //output << hex << "[MUL]\t" << insAddr << ": " << insDis;
    //output << " " << REG_StringShort(reg1) << " " << REG_StringShort(reg2) << " " << imm << endl;
    //output << hex << "\t\t\tsize: " << size << endl;

    if (isRegisterTainted(reg2)) {
        // TODO 正确打印 mul reg1, reg2, imm 指令的输出格式
        tracelog_regimm(insAddr, insDis, reg2, val2, imm, size);

        taintRegister(reg1, getRegisterOffset(reg2), size);
    }
}

/**
 * mul reg, mem, imm
 */
VOID traceMULRegMemImm(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, ADDRINT addr, UINT32 size, UINT64 imm)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    if (mem.tainted) {
        // TODO 正确打印 mul reg1, mem, imm 指令的输出格式
        tracelog_memimm(insAddr, insDis, addr, memval, imm, size);
        taintRegister(reg, mem.offset, size);
    }
}

/**
 * xchg reg, reg
 * 这条是数据转移指令，不需要打印日志
 */
VOID traceXCHGRegReg(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    if (reg1 == reg2)
        return;
#ifdef DEBUG
    tracelog_regreg(insAddr, insDis, reg1, val1, reg2, val2, size);
#endif

    UINT64 const* offreg1 = getRegisterOffset(reg1);
    UINT64 const* offreg2 = getRegisterOffset(reg2);
    if (isRegisterTainted(reg1) && isRegisterTainted(reg2)) {
        UINT64 off1[REGISTER_WIDTH];
        UINT64 off2[REGISTER_WIDTH];
        // swap
        copy_offset(off1, offreg2, size);
        copy_offset(off2, offreg1, size);
        taintRegister(reg1, off1, size);
        taintRegister(reg2, off2, size);
    }
    // reg1 -> reg2
    else if (isRegisterTainted(reg1)) {
        taintRegister(reg2, getRegisterOffset(reg1), size);
        clearRegister(reg1, size);
    }
    // reg1 <- reg2
    else if (isRegisterTainted(reg2)) {
        taintRegister(reg1, getRegisterOffset(reg2), size);
        clearRegister(reg2, size);
    }
}

/**
 * xchg mem, reg
 */
VOID traceXCHGMemReg(ADDRINT insAddr, string insDis, UINT32 opCount, ADDRINT addr, REG reg, ADDRINT val, UINT32 size)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 const* offset = getRegisterOffset(reg);
#ifdef DEBUG
    UINT64 memval = read_uint((UINT8*)addr, size);
    tracelog_memreg(insAddr, insDis, addr, memval, reg, val, size);
#endif

    if (mem.tainted && isRegisterTainted(reg)) {
        // mem <- reg
        addTaintBlock(addr, offset, size);
        // reg <- tmp
        taintRegister(reg, mem.offset, size);
    }
    // reg <- tmp
    else if (mem.tainted) {
        taintRegister(reg, mem.offset, size);
        removeTaintBlock(addr, size);
    }
    // mem <- reg
    else if (isRegisterTainted(reg)) {
        addTaintBlock(addr, offset, size);
        clearRegister(reg, size);
    }
}

/**
 * xchg reg, mem
 */
VOID traceXCHGRegMem(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, ADDRINT addr, UINT32 size)
{
    BUG_ON(size > REGISTER_WIDTH);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 const* offset = getRegisterOffset(reg);
#ifdef DEBUG
    UINT64 memval = read_uint((UINT8*)addr, size);
    tracelog_regmem(insAddr, insDis, reg, val, addr, memval, size);
#endif
    if (mem.tainted && isRegisterTainted(reg)) {
        // mem <- reg
        addTaintBlock(addr, offset, size);
        // reg <- tmp
        taintRegister(reg, mem.offset, size);
    }
    // reg <- tmp
    else if (mem.tainted) {
        taintRegister(reg, mem.offset, size);
        removeTaintBlock(addr, size);
    }
    // mem <- reg
    else if (isRegisterTainted(reg)) {
        addTaintBlock(addr, offset, size);
        clearRegister(reg, size);
    }
}

/**
 * cmpxchg r/m, r
 * if (dst == eax) {
 *     dst = src
 *     zf = 1
 * }
 * else {
 *    dst = eax
 *    zf = 0
 * }
 * 这条只需要记录比较部分
 */
/* temp cmpxchg handler */
VOID traceCMPXCHGRegReg(ADDRINT insAddr, string insDis, CONTEXT* ctx, UINT32 opCount, REG reg1, ADDRINT val1, REG reg2, ADDRINT val2, UINT32 size)
{
    REG rax = REG_EAX;
    switch (size) {
    case REG_SIZE_1:
        rax = REG_AL;
        break;
    case REG_SIZE_2:
        rax = REG_AX;
        break;
    case REG_SIZE_4:
        rax = REG_EAX;
        break;
#if defined(TARGET_IA32E)
    case REG_SIZE_8:
        rax = REG_RAX;
        break;
#endif
    default:
        UNREACHABLE();
    }

    UINT64 raxval = get_reg_value(ctx, rax);

    // 只记录比较信息
    if (isRegisterTainted(reg1) || isRegisterTainted(rax))
        tracelog_regreg(insAddr, insDis, reg1, val1, rax, raxval, size);

    if (val1 == raxval) {
        if (isRegisterTainted(reg2)) {
            taintRegister(reg1, getRegisterOffset(reg2), size);
        } else {
            clearRegister(reg1, size);
        }
    } else {
        if (isRegisterTainted(rax)) {
            taintRegister(reg1, getRegisterOffset(rax), size);
        } else {
            clearRegister(reg1, size);
        }
    }
}

/**
 * cmpxchg mem, reg
 */
VOID traceCMPXCHGMemReg(ADDRINT insAddr, string insDis, CONTEXT* ctx, UINT32 opCount, ADDRINT addr, REG reg2, ADDRINT val2, UINT32 size)
{
    REG rax = REG_EAX;
    switch (size) {
    case REG_SIZE_1:
        rax = REG_AL;
        break;
    case REG_SIZE_2:
        rax = REG_AX;
        break;
    case REG_SIZE_4:
        rax = REG_EAX;
        break;
#if defined(TARGET_IA32E)
    case REG_SIZE_8:
        rax = REG_RAX;
        break;
#endif
    default:
        UNREACHABLE();
    }

    UINT64 raxval = get_reg_value(ctx, rax);

    MemBlock mem;
    initMemTaint(&mem, addr, size);
    UINT64 memval = read_uint((UINT8*)addr, size);

    if (mem.tainted || isRegisterTainted(rax))
        tracelog_memreg(insAddr, insDis, addr, memval, rax, raxval, size);

    if (memval == val2) {
        if (isRegisterTainted(reg2)) {
            addTaintBlock(addr, getRegisterOffset(reg2), size);
        } else {
            removeTaintBlock(addr, size);
        }
    } else {
        if (isRegisterTainted(rax)) {
            addTaintBlock(addr, getRegisterOffset(rax), size);
        } else {
            removeTaintBlock(addr, size);
        }
    }
}

/**
 * bswap reg, 支持是 32 和 64 位
 */
VOID traceBSWAP(ADDRINT insAddr, string insDis, UINT32 opCount, REG reg, ADDRINT val, UINT32 size)
{
    BUG_ON(size < 4);

    if (isRegisterTainted(reg)) {
        tracelog_reg(insAddr, insDis, reg, val, size);

        UINT64 offset[REGISTER_WIDTH];
        copy_offset(offset, getRegisterOffset(reg), size);
        reverse(offset, offset+size);
        taintRegister(reg, offset, size);
    }
}

/**
 * jmp eax
 * result 就是 eax 的值, result == val
 */
void trace_jmpreg(ADDRINT addr, string const& disasm, ADDRINT result, REG reg, UINT64 val, UINT32 size)
{
    BUG_ON(result != val);
    if (isRegisterTainted(reg)) {
        tracelog_jmpreg(addr, disasm, result, reg, val, size);
    }
}

/**
 * jmp [eax+4*ebx+0x22]
 * 这里的 result 是 eax+4*ebx+0x22 的值，不是 jmp 跳到的地址
 * NOTE [rip+0x22] 寻址的不同，实际访问的地址
 *      EffectiveAddress = rip + 0x22 + len(ins)
 *      因为插桩在指令执行前，当前 rip 处于指令起始地址，
 *      取指完成后 rip 指向下一条地址，此时寄存器 rip 为 rip_old + len(ins)
 */
void trace_jmpmem(ADDRINT addr, string const& disasm, CONTEXT* ctx, ADDRINT result, REG base, REG idx, UINT32 scale, UINT64 disp, UINT32 inssize, UINT32 size)
{
    UINT64 bval = 0, ival = 0;
    if (REG_valid(base)) {
        bval = get_reg_value(ctx, base);
        if (REG_RIP == base || REG_EIP == base || REG_IP == base)
            bval += inssize;
    }
    if (REG_valid(idx))
        ival = get_reg_value(ctx, idx);

    BUG_ON(!IS_POWER_OF2(scale));
    BUG_ON(result != (bval + scale * ival + disp));

    if (REG_valid(base) && isRegisterTainted(base)) {
        tracelog_jmpmem(addr, disasm, result, base, bval, scale, idx, ival, disp, size);
        return;
    }

    if (REG_valid(idx) && isRegisterTainted(idx)) {
        tracelog_jmpmem(addr, disasm, result, base, bval, scale, idx, ival, disp, size);
        return;
    }
}

/**
 * 条件跳转指令的记录，只需要名字即可
 */
void trace_condjmp(ADDRINT addr, string const& disasm)
{
        if (cmp_tainted) {
            cmp_tainted = false;
            tracelog_ins(addr, disasm);
        }
}
