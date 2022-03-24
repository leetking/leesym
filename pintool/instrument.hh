#ifndef INSTRUMENT_HH__
#define INSTRUMENT_HH__

#include "pin.H"

#include <fstream>

extern ofstream logfile;

enum {
    REG_SIZE_1 = 1,
    REG_SIZE_2 = 2,
    REG_SIZE_4 = 4,
    REG_SIZE_8 = 8,     // 8bytes, 64 bits
    REG_SIZE_16 = 16,
    REG_SIZE_32 = 32,
    REG_SIZE_64 = 64,
};

enum {
    INVALID_ADDRESS = (UINT64)-1,
    INVALID_OFFSET = (UINT64)-1,
};
// max 512 bits
enum {
    REGISTER_WIDTH = 64,    // 64 bytes
};
#define REGISTER_INVALID REG_LAST
#define REGISTER_MAX     (REG_MACHINE_LAST+1)

#define get_bitmap(map, offset) (map & (0x1ULL<<(offset)))
#define set_bitmap(map, offset) (map |= (0x1ULL<<(offset)))
#define clr_bitmap(map, offset) (map &= (~(0x1ULL<<(offset))))
//#define merge_bitmap(map1, map2) ((map1) |= (map2))

// 记录寄存器哪些字节被污染, 实际寄存器最大不超过 64 字节吧, 通常也就 8 字节大
struct Register {
public:
    Register();
    Register(UINT64 const* offs, UINT32 size);

    UINT64 tainted;
    UINT64 offset[REGISTER_WIDTH];
};

struct MemBlock {
    UINT64 address;
    UINT64 tainted;
    UINT64 offset[REGISTER_WIDTH];
};

struct Byte {
    UINT64 address;
    UINT64 offset;
    bool direct;    // 字节是否直接来自输入

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

bool isByteTainted(UINT64 address);
void addTaintByte(UINT64 address, UINT64 offset);
void removeTaintByte(UINT64 address);
bool isBlockTainted(UINT64 addr, UINT32 size);
void addTaintBlock(UINT64 address, UINT64 const* offset, UINT32 size);
void removeTaintBlock(UINT64 address, UINT32 size);
// TODO remove below interfaces
Byte* getTaintByte(UINT64 address);

bool isRegisterOffsetTainted(REG reg, UINT32 offset);
void taintRegisterOffset(REG reg, UINT32 offset, UINT64 val);
UINT64 getRegisterOffset(REG reg, UINT32 offset);
void clearRegisterOffset(REG reg, UINT32 offset);
bool isRegisterTainted(REG reg);
void taintRegister(REG reg, UINT64 const* offset, UINT32 size);
UINT64 const* getRegisterOffset(REG reg);
void clearRegister(REG reg, UINT32 size);
// TODO remove below interfaces
Register* getTaintRegister(REG reg);

#endif // INSTRUMENT_HH__
