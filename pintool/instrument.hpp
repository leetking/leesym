#ifndef INTRIGUER_INSTRUMENT_HPP_
#define INTRIGUER_INSTRUMENT_HPP_

#include "pin.H"

enum {
    REG_SIZE_1 = 1,
    REG_SIZE_2 = 2,
    REG_SIZE_4 = 4,
    REG_SIZE_8 = 8,
    REG_SIZE_16 = 16,
    REG_SIZE_32 = 32,
};

// max 512 bits
enum { REGISTER_WIDTH = 64 };

#define get_bitmap(map, offset) (map & (0x1UL<<(offset)))
#define set_bitmap(map, offset) (map |= (0x1UL<<(offset)))
#define clr_bitmap(map, offset) (map &= (~(0x1UL<<(offset))))
//#define merge_bitmap(map1, map2) ((map1) |= (map2))
// 记录寄存器哪些字节被污染, 实际寄存器最大不超过 64 字节吧, 通常也就 8 字节大
struct Register {
    REG reg;
    UINT64 bitmap;
    UINT64 offset[REGISTER_WIDTH];
};

struct MemBlock {
    UINT64 address;
    UINT64 bitmap;
    UINT64 offset[32];
};

struct Byte {
    UINT64 address;
    UINT64 offset;
};

enum {
    PIN_PAGE_SIZE = 12,
    PIN_PAGE_SIZE_POW2 = (0x1 << PIN_PAGE_SIZE),
};
// page_base: 页号
#define page_base(addr) ((addr) >> PIN_PAGE_SIZE)
// page_addr: 页内偏移量
#define page_addr(addr) ((addr) & (PIN_PAGE_SIZE_POW2-1))
struct Page {
    UINT64 base;
    vector<Byte*> vecAddressTainted;
};

bool checkAlreadyRegTaintedOffset(REG reg, UINT8 offset);
bool checkAlreadyRegTainted(REG reg);

Byte* getTaintMemPointer(UINT64 address);
bool checkAlreadyMemTainted(UINT64 address);

VOID removeMemTainted(UINT64 address);
VOID removeMemTainted(UINT64 address, UINT64 size);
VOID addMemTainted(UINT64 address, UINT64 offset);
VOID addMemTainted(UINT64 address, UINT64 size, UINT64 bitmap, UINT64 offset[]);

Register* getTaintRegPointer(REG reg);
void pushTaintReg(REG reg, UINT64 bitmap, UINT64 offset[], UINT64 size);
bool taintReg(REG reg, UINT64 bitmap, UINT64 offset[]);
bool removeRegTainted(REG reg);

extern ofstream output;

#endif
