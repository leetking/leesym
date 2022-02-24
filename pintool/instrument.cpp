
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <list>

#if !defined(TARGET_WINDOWS)
#include <sys/syscall.h>
#endif

#include "instrument.hpp"

using namespace std;

// 记录内存被污染的情况
list<Page*> g_pages;
// 记录寄存器被污染的情况
list<Register*> g_registers;

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

void removeTaintBlock(UINT64 addr, UINT64 size)
{
    for(UINT64 i = 0; i < size; i++)
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
    g_pages.push_front(page);
}

void addTaintBlock(UINT64 address, UINT64 size, UINT64 bitmap, UINT64 offset[])
{
    // assert(size is 1, 2, 4, 8, 16 etc)
    for (UINT64 i = 0; i < size; i++) {

        //taint mem if reg offset tainted
        if (get_bitmap(bitmap, i)) {
            addTaintByte(address+i, offset[i]);

        //remove mem taint if reg offset is not taint
        } else {
            removeTaintByte(address+i);
        }
    }
}


// operations for registers
Register* getTaintRegister(REG reg)
{
    for (auto registor : g_registers) {
        if (registor->reg == reg)
            return registor;
    }

    return nullptr;
}

bool isRegisterOffsetTainted(REG reg, UINT8 offset)
{
    Register const* registor = getTaintRegister(reg);
    return registor && get_bitmap(registor->tainted, offset);
}

bool isRegisterTainted(REG reg)
{
    return getTaintRegister(reg);
}

void addTaintRegister(REG reg, UINT64 size, UINT64 bitmap, UINT64 offset[])
{
    // assert(size is 1, 2, 4, 8 etc)
#define cut_bitmap(map, bits) (map &= ((0x1<<(bits)) - 1))
    cut_bitmap(bitmap, size);

    Register* new_reg = new Register(reg, bitmap, offset);
    for (auto& registor : g_registers) {
        if (registor->reg == reg) {
            delete registor;
            registor = new_reg;
            return;
        }
    }

    // new register
    g_registers.push_front(new_reg);
#undef cut_bitmap
}

/* TODO: correctly handle registers*/
bool taintReg(REG reg, UINT64 bitmap, UINT64 offset[])
{
    if (reg == REGISTER_INVALID)
        return false;

    switch (reg) {
#if defined(TARGET_IA32E)
    case REG_RAX:
        addTaintRegister(REG_RAX, REG_SIZE_8, bitmap, offset);
#endif
    case REG_EAX:
        addTaintRegister(REG_EAX, REG_SIZE_4, bitmap, offset);
    case REG_AX:
        addTaintRegister(REG_AX, REG_SIZE_2, bitmap, offset);
    case REG_AH:
        addTaintRegister(REG_AH, REG_SIZE_1, bitmap, offset);
    case REG_AL:
        if(reg == REG_AH)
            break;
        addTaintRegister(REG_AL, REG_SIZE_1, bitmap, offset);
        break;

#if defined(TARGET_IA32E)
    case REG_RBX:
        addTaintRegister(REG_RBX, REG_SIZE_8, bitmap, offset);
#endif
    case REG_EBX:
        addTaintRegister(REG_EBX, REG_SIZE_4, bitmap, offset);
    case REG_BX:
        addTaintRegister(REG_BX, REG_SIZE_2, bitmap, offset);
    case REG_BH:
        addTaintRegister(REG_BH, REG_SIZE_1, bitmap, offset);
    case REG_BL:
        if(reg == REG_BH)
            break;
        addTaintRegister(REG_BL, REG_SIZE_1, bitmap, offset);
        break;

#if defined(TARGET_IA32E)
    case REG_RCX:
        addTaintRegister(REG_RCX, REG_SIZE_8, bitmap, offset);
#endif
    case REG_ECX:
        addTaintRegister(REG_ECX, REG_SIZE_4, bitmap, offset);
    case REG_CX:
        addTaintRegister(REG_CX, REG_SIZE_2, bitmap, offset);
    case REG_CH:
        addTaintRegister(REG_CH, REG_SIZE_1, bitmap, offset);
    case REG_CL:
        if(reg == REG_CH)
            break;
        addTaintRegister(REG_CL, REG_SIZE_1, bitmap, offset);
        break;

#if defined(TARGET_IA32E)
    case REG_RDX:
        addTaintRegister(REG_RDX, REG_SIZE_8, bitmap, offset);
#endif
    case REG_EDX:
        addTaintRegister(REG_EDX, REG_SIZE_4, bitmap, offset);
    case REG_DX:
        addTaintRegister(REG_DX, REG_SIZE_2, bitmap, offset);
    case REG_DH:
        addTaintRegister(REG_DH, REG_SIZE_1, bitmap, offset);
    case REG_DL:
        if(reg == REG_DH)
            break;
        addTaintRegister(REG_DL, REG_SIZE_1, bitmap, offset);
        break;

#if defined(TARGET_IA32E)
    case REG_RDI:
        addTaintRegister(REG_RDI, REG_SIZE_8, bitmap, offset);
#endif
    case REG_EDI:
        addTaintRegister(REG_EDI, REG_SIZE_4, bitmap, offset);
    case REG_DI:
        addTaintRegister(REG_DI, REG_SIZE_2, bitmap, offset);
#if defined(TARGET_IA32E)
    case REG_DIL:
        addTaintRegister(REG_DIL, REG_SIZE_1, bitmap, offset);
#endif
        break;

#if defined(TARGET_IA32E)
    case REG_RSI:
        addTaintRegister(REG_RSI, REG_SIZE_8, bitmap, offset);
#endif
    case REG_ESI:
        addTaintRegister(REG_ESI, REG_SIZE_4, bitmap, offset);
    case REG_SI:
        addTaintRegister(REG_SI, REG_SIZE_2, bitmap, offset);
#if defined(TARGET_IA32E)
    case REG_SIL:
        addTaintRegister(REG_SIL, REG_SIZE_1, bitmap, offset);
#endif
        break;

#if defined(TARGET_IA32E)
    case REG_R8:
        addTaintRegister(REG_R8, REG_SIZE_8, bitmap, offset);
    case REG_R8D:
        addTaintRegister(REG_R8D, REG_SIZE_4, bitmap, offset);
    case REG_R8W:
        addTaintRegister(REG_R8W, REG_SIZE_2, bitmap, offset);
    case REG_R8B:
        addTaintRegister(REG_R8B, REG_SIZE_1, bitmap, offset);
        break;

    case REG_R9:
        addTaintRegister(REG_R9, REG_SIZE_8, bitmap, offset);
    case REG_R9D:
        addTaintRegister(REG_R9D, REG_SIZE_4, bitmap, offset);
    case REG_R9W:
        addTaintRegister(REG_R9W, REG_SIZE_2, bitmap, offset);
    case REG_R9B:
        addTaintRegister(REG_R9B, REG_SIZE_1, bitmap, offset);
        break;

    case REG_R10:
        addTaintRegister(REG_R10, REG_SIZE_8, bitmap, offset);
    case REG_R10D:
        addTaintRegister(REG_R10D, REG_SIZE_4, bitmap, offset);
    case REG_R10W:
        addTaintRegister(REG_R10W, REG_SIZE_2, bitmap, offset);
    case REG_R10B:
        addTaintRegister(REG_R10B, REG_SIZE_1, bitmap, offset);
        break;

    case REG_R11:
        addTaintRegister(REG_R11, REG_SIZE_8, bitmap, offset);
    case REG_R11D:
        addTaintRegister(REG_R11D, REG_SIZE_4, bitmap, offset);
    case REG_R11W:
        addTaintRegister(REG_R11W, REG_SIZE_2, bitmap, offset);
    case REG_R11B:
        addTaintRegister(REG_R11B, REG_SIZE_1, bitmap, offset);
        break;

    case REG_R12:
        addTaintRegister(REG_R12, REG_SIZE_8, bitmap, offset);
    case REG_R12D:
        addTaintRegister(REG_R12D, REG_SIZE_4, bitmap, offset);
    case REG_R12W:
        addTaintRegister(REG_R12W, REG_SIZE_2, bitmap, offset);
    case REG_R12B:
        addTaintRegister(REG_R12B, REG_SIZE_1, bitmap, offset);
        break;

    case REG_R13:
        addTaintRegister(REG_R13, REG_SIZE_8, bitmap, offset);
    case REG_R13D:
        addTaintRegister(REG_R13D, REG_SIZE_4, bitmap, offset);
    case REG_R13W:
        addTaintRegister(REG_R13W, REG_SIZE_2, bitmap, offset);
    case REG_R13B:
        addTaintRegister(REG_R13B, REG_SIZE_1, bitmap, offset);
        break;

    case REG_R14:
        addTaintRegister(REG_R14, REG_SIZE_8, bitmap, offset);
    case REG_R14D:
        addTaintRegister(REG_R14D, REG_SIZE_4, bitmap, offset);
    case REG_R14W:
        addTaintRegister(REG_R14W, REG_SIZE_2, bitmap, offset);
    case REG_R14B:
        addTaintRegister(REG_R14B, REG_SIZE_1, bitmap, offset);
        break;

    case REG_R15:
        addTaintRegister(REG_R15, REG_SIZE_8, bitmap, offset);
    case REG_R15D:
        addTaintRegister(REG_R15D, REG_SIZE_4, bitmap, offset);
    case REG_R15W:
        addTaintRegister(REG_R15W, REG_SIZE_2, bitmap, offset);
    case REG_R15B:
        addTaintRegister(REG_R15B, REG_SIZE_1, bitmap, offset);
        break;
#endif // TARGET_IA32E

    case REG_YMM0:
        addTaintRegister(REG_YMM0, REG_SIZE_32, bitmap, offset);
    case REG_XMM0:
        addTaintRegister(REG_XMM0, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM1:
        addTaintRegister(REG_YMM1, REG_SIZE_32, bitmap, offset);
    case REG_XMM1:
        addTaintRegister(REG_XMM1, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM2:
        addTaintRegister(REG_YMM2, REG_SIZE_32, bitmap, offset);
    case REG_XMM2:
        addTaintRegister(REG_XMM2, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM3:
        addTaintRegister(REG_YMM3, REG_SIZE_32, bitmap, offset);
    case REG_XMM3:
        addTaintRegister(REG_XMM3, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM4:
        addTaintRegister(REG_YMM4, REG_SIZE_32, bitmap, offset);
    case REG_XMM4:
        addTaintRegister(REG_XMM4, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM5:
        addTaintRegister(REG_YMM5, REG_SIZE_32, bitmap, offset);
    case REG_XMM5:
        addTaintRegister(REG_XMM5, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM6:
        addTaintRegister(REG_YMM6, REG_SIZE_32, bitmap, offset);
    case REG_XMM6:
        addTaintRegister(REG_XMM6, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM7:
        addTaintRegister(REG_YMM7, REG_SIZE_32, bitmap, offset);
    case REG_XMM7:
        addTaintRegister(REG_XMM7, REG_SIZE_16, bitmap, offset);

        break;

#if defined(TARGET_IA32E)
    case REG_YMM8:
        addTaintRegister(REG_YMM8, REG_SIZE_32, bitmap, offset);
    case REG_XMM8:
        addTaintRegister(REG_XMM8, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM9:
        addTaintRegister(REG_YMM9, REG_SIZE_32, bitmap, offset);
    case REG_XMM9:
        addTaintRegister(REG_XMM9, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM10:
        addTaintRegister(REG_YMM10, REG_SIZE_32, bitmap, offset);
    case REG_XMM10:
        addTaintRegister(REG_XMM10, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM11:
        addTaintRegister(REG_YMM11, REG_SIZE_32, bitmap, offset);
    case REG_XMM11:
        addTaintRegister(REG_XMM11, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM12:
        addTaintRegister(REG_YMM12, REG_SIZE_32, bitmap, offset);
    case REG_XMM12:
        addTaintRegister(REG_XMM12, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM13:
        addTaintRegister(REG_YMM13, REG_SIZE_32, bitmap, offset);
    case REG_XMM13:
        addTaintRegister(REG_XMM13, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM14:
        addTaintRegister(REG_YMM14, REG_SIZE_32, bitmap, offset);
    case REG_XMM14:
        addTaintRegister(REG_XMM14, REG_SIZE_16, bitmap, offset);
        break;

    case REG_YMM15:
        addTaintRegister(REG_YMM15, REG_SIZE_32, bitmap, offset);
    case REG_XMM15:
        addTaintRegister(REG_XMM15, REG_SIZE_16, bitmap, offset);
        break;
#endif // TARGET_IA32E

#if defined(TARGET_IA32E)
    case REG_RBP:
        addTaintRegister(REG_RBP, REG_SIZE_8, bitmap, offset);
#endif
    case REG_EBP:
        addTaintRegister(REG_EBP, REG_SIZE_4, bitmap, offset);
        break;

    default:
        return false;
    }

    return true;
}

bool removeTaintRegister(REG reg)
{
    if (REGISTER_INVALID == reg)
        return false;
    Register* r;
    switch (reg) {
#if defined(TARGET_IA32E)
    case REG_RAX:
        r = getTaintRegister(REG_RAX);
        g_registers.remove(r);
        delete r;
#endif
    case REG_EAX:
        r = getTaintRegister(REG_EAX);
        g_registers.remove(r);
        delete r;
    case REG_AX:
        r = getTaintRegister(REG_AX);
        g_registers.remove(r);
        delete r;
    case REG_AH:
        r = getTaintRegister(REG_AH);
        g_registers.remove(r);
        delete r;
    case REG_AL:
        if (reg == REG_AH)
            break;
        r = getTaintRegister(REG_AL);
        g_registers.remove(r);
        delete r;
        break;

#if defined(TARGET_IA32E)
    case REG_RBX:
        r = getTaintRegister(REG_RBX);
        g_registers.remove(r);
        delete r;
#endif
    case REG_EBX:
        r = getTaintRegister(REG_EBX);
        g_registers.remove(r);
        delete r;
    case REG_BX:
        r = getTaintRegister(REG_BX);
        g_registers.remove(r);
        delete r;
    case REG_BH:
        r = getTaintRegister(REG_BH);
        g_registers.remove(r);
        delete r;
    case REG_BL:
        if (reg == REG_BH)
            break;
        r = getTaintRegister(REG_BL);
        g_registers.remove(r);
        delete r;
        break;

#if defined(TARGET_IA32E)
    case REG_RCX:
        r = getTaintRegister(REG_RCX);
        g_registers.remove(r);
        delete r;
#endif
    case REG_ECX:
        r = getTaintRegister(REG_ECX);
        g_registers.remove(r);
        delete r;
    case REG_CX:
        r = getTaintRegister(REG_CX);
        g_registers.remove(r);
        delete r;
    case REG_CH:
        r = getTaintRegister(REG_CH);
        g_registers.remove(r);
        delete r;
    case REG_CL:
        if (reg == REG_CH)
            break;
        r = getTaintRegister(REG_CL);
        g_registers.remove(r);
        delete r;
        break;

#if defined(TARGET_IA32E)
    case REG_RDX:
        r = getTaintRegister(REG_RDX);
        g_registers.remove(r);
        delete r;
#endif
    case REG_EDX:
        r = getTaintRegister(REG_EDX);
        g_registers.remove(r);
        delete r;
    case REG_DX:
        r = getTaintRegister(REG_DX);
        g_registers.remove(r);
        delete r;
    case REG_DH:
        r = getTaintRegister(REG_DH);
        g_registers.remove(r);
        delete r;
    case REG_DL:
        if (reg == REG_DH)
            break;
        r = getTaintRegister(REG_DL);
        g_registers.remove(r);
        delete r;
        break;

#if defined(TARGET_IA32E)
    case REG_RDI:
        r = getTaintRegister(REG_RDI);
        g_registers.remove(r);
        delete r;
#endif
    case REG_EDI:
        r = getTaintRegister(REG_EDI);
        g_registers.remove(r);
        delete r;
    case REG_DI:
        r = getTaintRegister(REG_DI);
        g_registers.remove(r);
        delete r;
#if defined(TARGET_IA32E)
    case REG_DIL:
        r = getTaintRegister(REG_DIL);
        g_registers.remove(r);
        delete r;
#endif
        break;

#if defined(TARGET_IA32E)
    case REG_RSI:
        r = getTaintRegister(REG_RSI);
        g_registers.remove(r);
        delete r;
#endif
    case REG_ESI:
        r = getTaintRegister(REG_ESI);
        g_registers.remove(r);
        delete r;
    case REG_SI:
        r = getTaintRegister(REG_SI);
        g_registers.remove(r);
        delete r;
#if defined(TARGET_IA32E)
    case REG_SIL:
        r = getTaintRegister(REG_SIL);
        g_registers.remove(r);
        delete r;
#endif
        break;

#if defined(TARGET_IA32E)
    case REG_R8:
        r = getTaintRegister(REG_R8);
        g_registers.remove(r);
        delete r;
    case REG_R8D:
        r = getTaintRegister(REG_R8D);
        g_registers.remove(r);
        delete r;
    case REG_R8W:
        r = getTaintRegister(REG_R8W);
        g_registers.remove(r);
        delete r;
    case REG_R8B:
        r = getTaintRegister(REG_R8B);
        g_registers.remove(r);
        delete r;
        break;

    case REG_R9:
        r = getTaintRegister(REG_R9);
        g_registers.remove(r);
        delete r;
    case REG_R9D:
        r = getTaintRegister(REG_R9D);
        g_registers.remove(r);
        delete r;
    case REG_R9W:
        r = getTaintRegister(REG_R9W);
        g_registers.remove(r);
        delete r;
    case REG_R9B:
        r = getTaintRegister(REG_R9B);
        g_registers.remove(r);
        delete r;
        break;

    case REG_R10:
        r = getTaintRegister(REG_R10);
        g_registers.remove(r);
        delete r;
    case REG_R10D:
        r = getTaintRegister(REG_R10D);
        g_registers.remove(r);
        delete r;
    case REG_R10W:
        r = getTaintRegister(REG_R10W);
        g_registers.remove(r);
        delete r;
    case REG_R10B:
        r = getTaintRegister(REG_R10B);
        g_registers.remove(r);
        delete r;
        break;

    case REG_R11:
        r = getTaintRegister(REG_R11);
        g_registers.remove(r);
        delete r;
    case REG_R11D:
        r = getTaintRegister(REG_R11D);
        g_registers.remove(r);
        delete r;
    case REG_R11W:
        r = getTaintRegister(REG_R11W);
        g_registers.remove(r);
        delete r;
    case REG_R11B:
        r = getTaintRegister(REG_R11B);
        g_registers.remove(r);
        delete r;
        break;

    case REG_R12:
        r = getTaintRegister(REG_R12);
        g_registers.remove(r);
        delete r;
    case REG_R12D:
        r = getTaintRegister(REG_R12D);
        g_registers.remove(r);
        delete r;
    case REG_R12W:
        r = getTaintRegister(REG_R12W);
        g_registers.remove(r);
        delete r;
    case REG_R12B:
        r = getTaintRegister(REG_R12B);
        g_registers.remove(r);
        delete r;
        break;

    case REG_R13:
        r = getTaintRegister(REG_R13);
        g_registers.remove(r);
        delete r;
    case REG_R13D:
        r = getTaintRegister(REG_R13D);
        g_registers.remove(r);
        delete r;
    case REG_R13W:
        r = getTaintRegister(REG_R13W);
        g_registers.remove(r);
        delete r;
    case REG_R13B:
        r = getTaintRegister(REG_R13B);
        g_registers.remove(r);
        delete r;
        break;

    case REG_R14:
        r = getTaintRegister(REG_R14);
        g_registers.remove(r);
        delete r;
    case REG_R14D:
        r = getTaintRegister(REG_R14D);
        g_registers.remove(r);
        delete r;
    case REG_R14W:
        r = getTaintRegister(REG_R14W);
        g_registers.remove(r);
        delete r;
    case REG_R14B:
        r = getTaintRegister(REG_R14B);
        g_registers.remove(r);
        delete r;
        break;

    case REG_R15:
        r = getTaintRegister(REG_R15);
        g_registers.remove(r);
        delete r;
    case REG_R15D:
        r = getTaintRegister(REG_R15D);
        g_registers.remove(r);
        delete r;
    case REG_R15W:
        r = getTaintRegister(REG_R15W);
        g_registers.remove(r);
        delete r;
    case REG_R15B:
        r = getTaintRegister(REG_R15B);
        g_registers.remove(r);
        delete r;
        break;
#endif // TARGET_IA32E

    case REG_YMM0:
        r = getTaintRegister(REG_YMM0);
        g_registers.remove(r);
        delete r;
    case REG_XMM0:
        r = getTaintRegister(REG_XMM0);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM1:
        r = getTaintRegister(REG_YMM1);
        g_registers.remove(r);
        delete r;
    case REG_XMM1:
        r = getTaintRegister(REG_XMM1);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM2:
        r = getTaintRegister(REG_YMM2);
        g_registers.remove(r);
        delete r;
    case REG_XMM2:
        r = getTaintRegister(REG_XMM2);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM3:
        r = getTaintRegister(REG_YMM3);
        g_registers.remove(r);
        delete r;
    case REG_XMM3:
        r = getTaintRegister(REG_XMM3);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM4:
        r = getTaintRegister(REG_YMM4);
        g_registers.remove(r);
        delete r;
    case REG_XMM4:
        r = getTaintRegister(REG_XMM4);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM5:
        r = getTaintRegister(REG_YMM5);
        g_registers.remove(r);
        delete r;
    case REG_XMM5:
        r = getTaintRegister(REG_XMM5);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM6:
        r = getTaintRegister(REG_YMM6);
        g_registers.remove(r);
        delete r;
    case REG_XMM6:
        r = getTaintRegister(REG_XMM6);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM7:
        r = getTaintRegister(REG_YMM7);
        g_registers.remove(r);
        delete r;
    case REG_XMM7:
        r = getTaintRegister(REG_XMM7);
        g_registers.remove(r);
        delete r;
        break;

#if defined(TARGET_IA32E)
    case REG_YMM8:
        r = getTaintRegister(REG_YMM8);
        g_registers.remove(r);
        delete r;
    case REG_XMM8:
        r = getTaintRegister(REG_XMM8);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM9:
        r = getTaintRegister(REG_YMM9);
        g_registers.remove(r);
        delete r;
    case REG_XMM9:
        r = getTaintRegister(REG_XMM9);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM10:
        r = getTaintRegister(REG_YMM10);
        g_registers.remove(r);
        delete r;
    case REG_XMM10:
        r = getTaintRegister(REG_XMM10);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM11:
        r = getTaintRegister(REG_YMM11);
        g_registers.remove(r);
        delete r;
    case REG_XMM11:
        r = getTaintRegister(REG_XMM11);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM12:
        r = getTaintRegister(REG_YMM12);
        g_registers.remove(r);
        delete r;
    case REG_XMM12:
        r = getTaintRegister(REG_XMM12);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM13:
        r = getTaintRegister(REG_YMM13);
        g_registers.remove(r);
        delete r;
    case REG_XMM13:
        r = getTaintRegister(REG_XMM13);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM14:
        r = getTaintRegister(REG_YMM14);
        g_registers.remove(r);
        delete r;
    case REG_XMM14:
        r = getTaintRegister(REG_XMM14);
        g_registers.remove(r);
        delete r;
        break;

    case REG_YMM15:
        r = getTaintRegister(REG_YMM15);
        g_registers.remove(r);
        delete r;
    case REG_XMM15:
        r = getTaintRegister(REG_XMM15);
        g_registers.remove(r);
        delete r;
        break;
#endif // TARGET_IA32E

#if defined(TARGET_IA32E)
    case REG_RBP:
        r = getTaintRegister(REG_RBP);
        g_registers.remove(r);
        delete r;
#endif
    case REG_EBP:
        r = getTaintRegister(REG_EBP);
        g_registers.remove(r);
        delete r;
        break;

    default:
        return false;
    }

    return true;
}
