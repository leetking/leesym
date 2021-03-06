#ifndef TRACE_HH__
#define TRACE_HH__

#include <string>

#include "pin.H"

// TODO 支持 128, 256 bits 寄存器的值
void tracelog_reg(UINT64 insAddr, std::string const& insDis, REG reg, UINT64 val, UINT32 size);
void tracelog_regimm(UINT64 insAddr, std::string const& insDis, REG reg, UINT64 val, UINT64 imm, UINT32 size);
void tracelog_regreg(UINT64 insAddr, std::string const& insDis, REG reg1, UINT64 val1, REG reg2, UINT64 val2, UINT32 size);
void tracelog_regreg(UINT64 insAddr, std::string const& insDis, REG reg1, UINT8 const* val1, REG reg2, UINT8 const* val2, UINT32 size);
void tracelog_regregimm(UINT64 insAddr, std::string const& insDis, REG reg1, UINT64 val1, REG reg2, UINT64 val2, UINT64 imm, UINT32 size);
void tracelog_regmem(UINT64 insAddr, std::string const& insDis, REG reg, UINT64 val1, ADDRINT addr, UINT64 val2, UINT32 size);
void tracelog_regmem(UINT64 insAddr, std::string const& insDis, REG reg, UINT8 const* val1, ADDRINT addr, UINT8 const* val2, UINT32 size);
void tracelog_regmemimm(UINT64 insAddr, std::string const& insDis, REG reg, UINT64 val1, ADDRINT addr, UINT64 val2, UINT64 imm, UINT32 size);
void tracelog_mem(UINT64 insAddr, std::string const& insDis, ADDRINT addr, UINT64 val,UINT32 size);
void tracelog_memimm(UINT64 insAddr, std::string const& insDis, ADDRINT addr, UINT64 val, UINT64 imm, UINT32 size);
void tracelog_memreg(UINT64 insAddr, std::string const& insDis, ADDRINT addr, UINT64 val1, REG reg, UINT64 val2, UINT32 size);
void tracelog_memmem(UINT64 insAddr, std::string const& insDis, ADDRINT addr1, UINT64 val1, ADDRINT addr2, UINT64 val2, UINT32 size);
void tracelog_memmem_addr(UINT64 insAddr, std::string const& insDis, ADDRINT addr1, ADDRINT addr2, UINT32 size);
void tracelog_leamem(UINT64 insaddr, string const& insdis,
        REG base, UINT64 bval,
        UINT32 scale,
        REG idx, UINT64 ival,
        UINT64 disp,
        UINT32 size);
void tracelog_jmpreg(UINT64 insaddr, string const& insdis, ADDRINT result, REG reg, UINT64 val, UINT32 size);
void tracelog_jmpmem(UINT64 insaddr, string const& insdis, ADDRINT result,
        REG base, UINT64 bval,
        UINT32 scale,
        REG idx, UINT64 ival,
        UINT64 disp,
        UINT32 size);
void tracelog_ins(UINT64 insaddr, string const& insdis);

#endif // TRACE_HH__
