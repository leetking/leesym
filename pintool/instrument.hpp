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

enum {
    INVALID_ADDRESS = (UINT64)-1,
    INVALID_OFFSET = (UINT64)-1,
};
// max 512 bits
enum {
    REGISTER_WIDTH = 64,
};
#define REGISTER_INVALID REG_LAST

#define get_bitmap(map, offset) (map & (0x1UL<<(offset)))
#define set_bitmap(map, offset) (map |= (0x1UL<<(offset)))
#define clr_bitmap(map, offset) (map &= (~(0x1UL<<(offset))))
//#define merge_bitmap(map1, map2) ((map1) |= (map2))

// 记录寄存器哪些字节被污染, 实际寄存器最大不超过 64 字节吧, 通常也就 8 字节大
struct Register {
    REG reg;
    UINT64 bitmap;
    UINT64 offset[REGISTER_WIDTH];

    Register():
        Register(REGISTER_INVALID, 0x0, nullptr) {
    }

    Register(REG r, UINT64 bits, UINT64 offs[])
        : reg(r), bitmap(bits) {
        for (UINT64 i = 0; i < REGISTER_WIDTH; ++i)
            offset[i] = INVALID_OFFSET;
        if (offs) {
            for (UINT64 i = 0; i < REGISTER_WIDTH; ++i) {
                if (get_bitmap(bits, i))
                    offset[i] = offs[i];
            }
        }
    }
};

struct MemBlock {
    UINT64 address;
    UINT64 bitmap;
    UINT64 offset[32];
};

struct Byte {
    UINT64 address;
    UINT64 offset;

    Byte()
        : Byte(INVALID_ADDRESS, INVALID_OFFSET) {
    }

    Byte(UINT64 addr, UINT64 off)
        : address(addr), offset(off) {
    }
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
    vector<Byte*> bytes;

    Page(UINT64 b)
        : Page(b, nullptr) {
    }

    Page(UINT64 b, Byte *byte)
        : base(b), bytes(PIN_PAGE_SIZE_POW2) {
            if (byte)
                bytes[page_addr(byte->address)] = byte;
    }

    // TODO Add deconstructor for Page
};

Byte* getTaintByte(UINT64 address);
bool isByteTainted(UINT64 address);
void addTaintByte(UINT64 address, UINT64 offset);
void addTaintBlock(UINT64 address, UINT64 size, UINT64 bitmap, UINT64 offset[]);
void removeTaintByte(UINT64 address);
void removeTaintBlock(UINT64 address, UINT64 size);

Register* getTaintRegister(REG reg);
bool isRegisterOffsetTainted(REG reg, UINT8 offset);
bool isRegisterTainted(REG reg);
void addTaintRegister(REG reg, UINT64 size, UINT64 bitmap, UINT64 offset[]);
bool taintReg(REG reg, UINT64 bitmap, UINT64 offset[]);
bool removeTaintRegister(REG reg);


extern ofstream output;

#endif
