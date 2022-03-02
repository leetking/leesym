#ifndef INTRIGUER_TRACE_HPP_
#define INTRIGUER_TRACE_HPP_

#include <string>

#include "pin.H"

// TODO 支持 128, 256 bits 寄存器的值
void tracelog_reg(UINT64 insAddr, std::string const& insDis, REG reg, UINT64 val, UINT64 size);
void tracelog_regimm(UINT64 insAddr, std::string const& insDis, REG reg, UINT64 val, UINT64 imm, UINT64 size);
void tracelog_regreg(UINT64 insAddr, std::string const& insDis, REG reg1, UINT64 val1, REG reg2, UINT64 val2, UINT64 size);
void tracelog_regregimm(UINT64 insAddr, std::string const& insDis, REG reg1, UINT64 val1, REG reg2, UINT64 val2, UINT64 imm, UINT64 size);
void tracelog_regmem(UINT64 insAddr, std::string const& insDis, REG reg, UINT64 val1, ADDRINT addr, INT64 val2, UINT64 size);
void tracelog_regmemimm(UINT64 insAddr, std::string const& insDis, REG reg, UINT64 val1, ADDRINT addr, UINT64 val2, UINT64 imm, UINT64 size);
void tracelog_mem(UINT64 insAddr, std::string const& insDis, ADDRINT addr, INT64 val,UINT64 size);
void tracelog_memimm(UINT64 insAddr, std::string const& insDis, ADDRINT addr, INT64 val, UINT64 imm, UINT64 size);
void tracelog_memreg(UINT64 insAddr, std::string const& insDis, ADDRINT addr, INT64 val1, REG reg, UINT64 val2, UINT64 size);
void tracelog_memmem(UINT64 insAddr, std::string const& insDis, ADDRINT addr1, INT64 val1, ADDRINT addr2, INT64 val2, UINT64 size);
void tracelog_memmem_addr(UINT64 insAddr, std::string const& insDis, ADDRINT addr1, ADDRINT addr2, UINT32 size);

#endif
