
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <list>

#if !defined(TARGET_WINDOWS)
#include <sys/syscall.h>
#endif

#include "instrument.hpp"
#include "common.h"         // import BUG_ON

using namespace std;

// 记录内存被污染的情况
vector<Page*> g_pages;
// 记录寄存器被污染的情况
vector<Register*> g_registers;

// operations for memory bytes
Byte* getTaintByte(UINT64 addr)
{
    for (auto page : g_pages) {
        // TODO Optimize with LRU algorithm
        if (page->base == page_base(addr))
            return page->bytes[page_addr(addr)];
    }

    return nullptr;
}

bool isByteTainted(UINT64 addr)
{
    return getTaintByte(addr);
}

void removeTaintByte(UINT64 addr)
{
    for (auto page : g_pages) {
        if (page->base == page_base(addr)) {
            delete page->bytes[page_addr(addr)];
            page->bytes[page_addr(addr)] = nullptr;
        }
    }
}

void removeTaintBlock(UINT64 addr, UINT32 size)
{
    for (UINT32 i = 0; i < size; i++)
        removeTaintByte(addr+i);
}

void addTaintByte(UINT64 addr, UINT64 offset)
{
    if (offset == INVALID_OFFSET)
        return;

    Byte* byte = new Byte(addr, offset);

    for (auto page : g_pages) {
        if (page->base == page_base(addr)) {
            delete page->bytes[page_addr(addr)];
            page->bytes[page_addr(addr)] = byte;
            return;
        }
    }

    // new page
    Page *page = new Page(page_base(addr), byte);
    g_pages.push_back(page);
}

void addTaintBlock(UINT64 addr, UINT64 const* offset, UINT32 size)
{
    // assert(size is 1, 2, 4, 8, 16 etc)
    for (UINT32 i = 0; i < size; i++) {
        //taint mem if reg offset tainted
        if (offset[i] != INVALID_OFFSET) {
            addTaintByte(addr+i, offset[i]);
        }
        //remove mem taint if reg offset is not taint
        else {
            removeTaintByte(addr+i);
        }
    }
}

static
REG get_reg_inner_name(REG reg)
{
    switch (reg) {
    case REG_AL:    // lower 1
    case REG_AH:    // upper 1
    case REG_AX:    // 2
    case REG_EAX:   // 4
#ifdef TARGET_IA32E
    case REG_RAX:   // 8
        return REG_RAX;
#else
        return REG_EAX;
#endif

    case REG_BL:    // lower 1
    case REG_BH:    // upper 1
    case REG_BX:
    case REG_EBX:
#ifdef TARGET_IA32E
    case REG_RBX:
        return REG_RBX;
#else
        return REG_EBX;
#endif

    case REG_CL:
    case REG_CH:
    case REG_CX:
    case REG_ECX:
#ifdef TARGET_IA32E
    case REG_RCX:
        return REG_RCX;
#else
        return REG_ECX;
#endif

    case REG_DL:
    case REG_DH:
    case REG_DX:
    case REG_EDX:
#ifdef TARGET_IA32E
    case REG_RDX:
        return REG_RDX;
#else
        return REG_EDX;
#endif

#ifdef TARGET_IA32E
    case REG_DIL:
#endif // TARGET_IA32E
    case REG_DI:
    case REG_EDI:
#ifdef TARGET_IA32E
    case REG_RDI:
        return REG_RDI;
#else
        return REG_EDI;
#endif

#ifdef TARGET_IA32E
    case REG_SIL:
#endif
    case REG_SI:
    case REG_ESI:
#ifdef TARGET_IA32E
    case REG_RSI:
        return REG_RSI;
#else
        return REG_ESI;
#endif

    case REG_EBP:
#ifdef TARGET_IA32E
    case REG_RBP:
        return REG_RBP;
#else
        return REG_EBP;
#endif

#ifdef TARGET_IA32E
    case REG_R8:
    case REG_R8D:
    case REG_R8W:
    case REG_R8B:
        return REG_R8;

    case REG_R9:
    case REG_R9D:
    case REG_R9W:
    case REG_R9B:
        return REG_R9;

    case REG_R10:
    case REG_R10D:
    case REG_R10W:
    case REG_R10B:
        return REG_R10;

    case REG_R11:
    case REG_R11D:
    case REG_R11W:
    case REG_R11B:
        return REG_R11;

    case REG_R12:
    case REG_R12D:
    case REG_R12W:
    case REG_R12B:
        return REG_R12;

    case REG_R13:
    case REG_R13D:
    case REG_R13W:
    case REG_R13B:
        return REG_R13;

    case REG_R14:
    case REG_R14D:
    case REG_R14W:
    case REG_R14B:
        return REG_R14;

    case REG_R15:
    case REG_R15D:
    case REG_R15W:
    case REG_R15B:
        return REG_R15;
#endif // TARGET_IA32E

    // xmm0 是 ymm0 的下半部
    case REG_YMM0:  // 32
    case REG_XMM0:  // 16
        return REG_YMM0;

    case REG_YMM1:
    case REG_XMM1:
        return REG_YMM1;

    case REG_YMM2:
    case REG_XMM2:
        return REG_YMM2;

    case REG_YMM3:
    case REG_XMM3:
        return REG_YMM3;

    case REG_YMM4:
    case REG_XMM4:
        return REG_YMM4;

    case REG_YMM5:
    case REG_XMM5:
        return REG_YMM5;

    case REG_YMM6:
    case REG_XMM6:
        return REG_YMM6;

    case REG_YMM7:
    case REG_XMM7:
        return REG_YMM7;

#ifdef TARGET_IA32E
    case REG_YMM8:
    case REG_XMM8:
        return REG_YMM8;

    case REG_YMM9:
    case REG_XMM9:
        return REG_YMM9;

    case REG_YMM10:
    case REG_XMM10:
        return REG_YMM10;

    case REG_YMM11:
    case REG_XMM11:
        return REG_YMM11;

    case REG_YMM12:
    case REG_XMM12:
        return REG_YMM12;

    case REG_YMM13:
    case REG_XMM13:
        return REG_YMM13;

    case REG_YMM14:
    case REG_XMM14:
        return REG_YMM14;

    case REG_YMM15:
    case REG_XMM15:
        return REG_YMM15;
#endif // TARGET_IA32

    // 目前只考虑能做数据存储的寄存器
    default:
        return reg;
    }
}

static inline
UINT32 get_reg_shift(REG reg)
{
    switch (reg) {
    case REG_AH:
    case REG_BH:
    case REG_CH:
    case REG_DH:
        return 1;
    default:
        return 0;
    }
}

Register::Register(REG reg)
    : Register(reg, nullptr, REGISTER_WIDTH)
{
}

Register::Register(REG r, UINT64 const* offset, UINT32 size)
    : reg(get_reg_inner_name(r)),
      tainted(0x0)
{
    BUG_ON(size > REG_Size(reg));
    for (UINT32 i = 0; i < REGISTER_WIDTH; ++i)
        this->offset[i] = INVALID_OFFSET;
    if (!offset)
        return;
    for (UINT32 i = 0; i < size; ++i) {
        if (offset[i] != INVALID_OFFSET) {
            this->offset[i] = offset[i];
            set_bitmap(tainted, i);
        }
    }
}

// operations for registers
Register* getTaintRegister(REG reg)
{
    BUG_ON(reg == REGISTER_INVALID);
    // inner reg
    REG ireg = get_reg_inner_name(reg);
    for (auto registor : g_registers) {
        if (registor->reg == ireg)
            return registor;
    }

    return nullptr;
}

bool isRegisterOffsetTainted(REG reg, UINT32 offset)
{
    //printf("offset: %d, regsize: %d %s\n", offset, REG_Size(reg), REG_StringShort(reg).c_str());
    BUG_ON(reg == REGISTER_INVALID);
    BUG_ON(offset >= REG_Size(reg));

    offset += get_reg_shift(reg);
    Register const* registor = getTaintRegister(reg);
    return registor && get_bitmap(registor->tainted, offset);
}

UINT64 const* getRegisterOffset(REG reg)
{
    Register* r = getTaintRegister(reg);
    UINT32 shift = get_reg_shift(reg);
    if (!r)
        return nullptr;
    return r->offset + shift;
}

bool isRegisterTainted(REG reg)
{
    BUG_ON(reg == REGISTER_INVALID);

    Register* r = getTaintRegister(reg);
    UINT32 size = REG_Size(reg);
    BUG_ON(size > 64 && "Unsupport register size > 64");
    UINT64 mask = (size == 64)? (~0x0): ((0x1<<size)-1);
    mask <<= get_reg_shift(reg);
    return r && (r->tainted & mask);
}

void taintRegister(REG reg, UINT64 const* offset, UINT32 size)
{
    BUG_ON(reg == REGISTER_INVALID);
    BUG_ON(offset == nullptr);
    BUG_ON(size > REG_Size(reg));

    Register* r = getTaintRegister(reg);
    if (!r) {
        r = new Register(reg, offset, size);
        g_registers.push_back(r);
        return;
    }

    // found r, update it
    UINT32 shift = get_reg_shift(reg);
    for (UINT32 i = shift; i < size+shift; ++i) {
        if (offset[i] != INVALID_OFFSET) {
            set_bitmap(r->tainted, i);
            r->offset[i] = offset[i];
        } else {
            clr_bitmap(r->tainted, i);
            r->offset[i] = INVALID_OFFSET;
        }
    }
}

void clearRegister(REG reg, UINT32 size)
{
    Register* r = getTaintRegister(reg);
    if (!r && !isRegisterTainted(reg))
        return;
    BUG_ON(size > REG_Size(reg));
    UINT32 shift = get_reg_shift(reg);
    UINT64 mask = (size==64)? (~0): ((1<<size)-1);
    mask <<= shift;
    mask = ~mask;       // e.g. 0b11111101
    r->tainted &= mask;
    for (UINT32 i = shift; i < size+shift; ++i)
        r->offset[i] = INVALID_OFFSET;
}
