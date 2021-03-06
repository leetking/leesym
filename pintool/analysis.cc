#include <cstdio>

#include <iostream>

#include <unistd.h>

#include "analysis.hh"
#include "instruction.hh"
#include "syscall.hh"

#define IARG_INSADDR(ins)       IARG_ADDRINT, INS_Address(ins)
#define IARG_NEXTADDR(ins)      IARG_ADDRINT, INS_Address(ins) + INS_Size(ins)
#define IARG_DISASM(ins)        IARG_PTR, new std::string(INS_Disassemble(ins))
#define IARG_REG(ins, opn)      IARG_UINT32, INS_OperandReg(ins, (opn))
#define IARG_REGVALUE(ins, opn) IARG_REG_VALUE, INS_RegR(ins, (opn))
#define IARG_OPWIDTH(ins, opn)  IARG_UINT32, (INS_OperandWidth(ins, (opn))/8)
#define IARG_OPIMM(ins, opn)    IARG_UINT64, INS_OperandImmediate(ins, (opn))
#define IARG_RDMEMSIZE(ins)     IARG_UINT32, INS_MemoryReadSize(ins)
#define IARG_WRMEMSIZE(ins)     IARG_UINT32, INS_MemoryWriteSize(ins)
#define IARG_BASEREG(ins, opn)  IARG_UINT32, INS_OperandMemoryBaseReg(ins, (opn))
#define IARG_INDEXREG(ins, opn) IARG_UINT32, INS_OperandMemoryIndexReg(ins, (opn))
#define IARG_SCALE(ins, opn)    IARG_UINT32, INS_OperandMemoryScale(ins, (opn))
#define IARG_DISPLACEMENT(ins, opn) IARG_UINT32, INS_OperandMemoryDisplacement(ins, (opn))

#ifdef SHOW_INS
static void print_instruction(ADDRINT insaddr, string const& disasm)
{
    printf("%lx: %s\n", insaddr, disasm.c_str());
}
#endif // SHOW_INS

// v 是用户自行传入的数据，这里没有使用
VOID Instruction(INS ins, VOID *v)
{
    if(!isTaintStart)
        return;

#ifdef SHOW_INS
    INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)print_instruction,
            IARG_INSADDR(ins),
            IARG_DISASM(ins),
            IARG_END);
#endif // SHOW_INS

    xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
    switch (ins_indx) {
    // 复制 DS:SI -> ES:DI
    case XED_ICLASS_MOVSQ:  // 8B
    case XED_ICLASS_MOVSD:  // 4B, == movsl
    case XED_ICLASS_MOVSW:  // 2B
    case XED_ICLASS_MOVSB:  // 1B
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)taintMOVS,
            // IARG_XXX 这是 funptr 参数的类型，INS_Address(ins) 为参数值
            IARG_ADDRINT, INS_Address(ins),
            // 指令的反汇编字符串
            IARG_PTR, new string(INS_Disassemble(ins)),
            // 指令的操作数个数
            IARG_UINT32, INS_OperandCount(ins),
            // 指令操作读内存的地址
            IARG_MEMORYREAD_EA,
            // 这条指令读取内存的大小, 1, 2, 4 or 8 B, 不一定和指令一致
            IARG_UINT32, INS_MemoryReadSize(ins),
            // 指令操作写内存的地址
            IARG_MEMORYWRITE_EA,
            // 写内存大小，和读大小一样，只能是 1, 2, 4 or 8 B
            IARG_UINT32, INS_MemoryWriteSize(ins),
            IARG_END);
        break;

    // 存储 RAX, EAX, AX, AL 的值到 [edi] 所指的内存
    case XED_ICLASS_STOSQ:
    case XED_ICLASS_STOSD:
    case XED_ICLASS_STOSW:
    case XED_ICLASS_STOSB:
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)taintSTOS,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),
            IARG_MEMORYWRITE_EA,
            IARG_UINT32, INS_MemoryWriteSize(ins),
            IARG_END);
        break;

    // 和 STOS 相反
    case XED_ICLASS_LODSQ:
    case XED_ICLASS_LODSD:
    case XED_ICLASS_LODSW:
    case XED_ICLASS_LODSB:
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)taintLODS,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_UINT32, INS_OperandCount(ins),
            IARG_MEMORYREAD_EA,
            IARG_UINT32, INS_MemoryReadSize(ins),
            IARG_END);
        break;

    case XED_ICLASS_CMPSQ:
    case XED_ICLASS_CMPSD:
    case XED_ICLASS_CMPSW:
    case XED_ICLASS_CMPSB:
        if(INS_RepPrefix(ins)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceCMPS,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_FIRST_REP_ITERATION,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD2_EA ,
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_REG_VALUE, INS_RepCountRegister(ins),
                IARG_END);
        }
        else{
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceCMPS,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_BOOL, true,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD2_EA,
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_UINT32, 1,
                IARG_END);
        }
        break;

    case XED_ICLASS_JB:     // <
    case XED_ICLASS_JBE:    // <=
    case XED_ICLASS_JCXZ:
    case XED_ICLASS_JECXZ:
    case XED_ICLASS_JL:     // <
    case XED_ICLASS_JLE:    // <=
    case XED_ICLASS_JNB:    // <=
    case XED_ICLASS_JNBE:   // >
    case XED_ICLASS_JNL:    // >=
    case XED_ICLASS_JNLE:   // >
    case XED_ICLASS_JNO:
    case XED_ICLASS_JNP:
    case XED_ICLASS_JNS:
    case XED_ICLASS_JNZ:
    case XED_ICLASS_JO:
    case XED_ICLASS_JP:
    case XED_ICLASS_JRCXZ:
    case XED_ICLASS_JS:
    case XED_ICLASS_JZ:
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)trace_condjmp,
                IARG_INSADDR(ins),
                IARG_DISASM(ins),
                IARG_END);
        break;
    //case XED_ICLASS_JMP_FAR:
    case XED_ICLASS_JMP:
        // jmp eax
        if (INS_OperandIsReg(ins, OP_0)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)trace_jmpreg,
                    IARG_INSADDR(ins),
                    IARG_DISASM(ins),
                    IARG_REGVALUE(ins, OP_0),
                    IARG_REG(ins, OP_0),
                    IARG_REGVALUE(ins, OP_0),
                    IARG_OPWIDTH(ins, OP_0),
                    IARG_END);
        }
        // jmp [reg1 + scale * reg2 + disp], 寻址
        // jmp [base + scale * index + disp]
        // jmp [rip + disp]
        else if (INS_OperandIsMemory(ins, OP_0)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)trace_jmpmem,
                    IARG_INSADDR(ins),
                    IARG_DISASM(ins),
                    IARG_CONTEXT,
                    IARG_MEMORYREAD_EA,
                    IARG_BASEREG(ins, OP_0),
                    IARG_INDEXREG(ins, OP_0),
                    IARG_SCALE(ins, OP_0),
                    IARG_DISPLACEMENT(ins, OP_0),
                    IARG_UINT32, INS_Size(ins),
                    IARG_RDMEMSIZE(ins),
                    IARG_END);
        }
        break;

    /* TODO */
    case XED_ICLASS_CALL_FAR:
    case XED_ICLASS_CALL_NEAR:

    case XED_ICLASS_LEAVE:

    case XED_ICLASS_RET_NEAR:
    case XED_ICLASS_RET_FAR:
        break;

    case XED_ICLASS_NOP:
        break;

    case XED_ICLASS_CMP:
    case XED_ICLASS_TEST:
        if(INS_MemoryOperandCount(ins) == 0){
            // cmp reg, reg
            if(!INS_OperandIsImmediate(ins, OP_1)){
                if(REG_is_xmm_ymm_zmm(INS_RegR(ins, OP_0)) || REG_is_mm(INS_RegR(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_RegR(ins, OP_1),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_REG_VALUE, INS_RegR(ins, OP_0),
                        IARG_UINT32, INS_RegR(ins, OP_1),
                        IARG_REG_VALUE, INS_RegR(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
            }
            // cmp reg, imm
            else{
                if(REG_is_xmm_ymm_zmm(INS_RegR(ins, OP_0)) || REG_is_mm(INS_RegR(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                } else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_REG_VALUE, INS_RegR(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
            }
        } else {
            //cmp reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                if(REG_is_xmm_ymm_zmm(INS_RegR(ins, OP_0)) || REG_is_mm(INS_RegR(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegMem,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_ADDRINT, 0,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPRegMem,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegR(ins, OP_0),
                        IARG_REG_VALUE, INS_RegR(ins, OP_0),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
            }
            //cmp mem, reg
            else if(INS_OperandIsReg(ins, 1)){
                if(REG_is_xmm_ymm_zmm(INS_RegR(ins, OP_0)) || REG_is_mm(INS_RegR(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPMemReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_RegR(ins, OP_1),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceCMPMemReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
            }
            //cmp mem, imm
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceCMPMemImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                    IARG_END);
            }
        }
        break;

    case XED_ICLASS_PCMPEQB:
    case XED_ICLASS_PCMPEQW:
    case XED_ICLASS_PCMPEQD:
    case XED_ICLASS_PCMPEQQ:

    case XED_ICLASS_PCMPGTB:
    case XED_ICLASS_PCMPGTW:
    case XED_ICLASS_PCMPGTD:
    case XED_ICLASS_PCMPGTQ:
        if (INS_OperandIsReg(ins, OP_0)) {
            // pcmpxx reg, reg
            if (INS_OperandIsReg(ins, OP_1)) {
                INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)tracePCMPRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_CONTEXT,
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_REG(ins, OP_0),
                        IARG_REG(ins, OP_1),
                        IARG_OPWIDTH(ins, OP_0),
                        IARG_END);
            }
            // pcmpxx reg, mem
            else if (INS_OperandIsMemory(ins, OP_2)) {
                INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)tracePCMPRegMem,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_CONTEXT,
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_REG(ins, OP_0),
                        IARG_MEMORYREAD_EA,
                        IARG_RDMEMSIZE(ins),
                        IARG_END);
            }
            else {
                INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_END);
            }
        }
        else {
            INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_END);
        }
        break;

    case XED_ICLASS_VPCMPEQB:
    case XED_ICLASS_VPCMPEQW:
    case XED_ICLASS_VPCMPEQD:
    case XED_ICLASS_VPCMPEQQ:

    case XED_ICLASS_VPCMPGTB:
    case XED_ICLASS_VPCMPGTW:
    case XED_ICLASS_VPCMPGTD:
    case XED_ICLASS_VPCMPGTQ:
        // vpcmp xmm1, xmm2, xmm3
        if (INS_OperandIsReg(ins, OP_2)) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)trace_vpcmp_rrr,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_CONTEXT,
                IARG_REG(ins, OP_0),
                IARG_REG(ins, OP_1),
                IARG_REG(ins, OP_2),
                IARG_END);
        }
        // vpcmp xmm1, xmm2, m128
        else if (INS_OperandIsMemory(ins, OP_2)) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)trace_vpcmp_rrm,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_CONTEXT,
                IARG_REG(ins, OP_0),
                IARG_REG(ins, OP_1),
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_END);
        }
        break;

    case XED_ICLASS_PUSH:
        //reg -> memory
        if(INS_OperandIsReg(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintMemReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }
        // memory -> memory
        else if(INS_OperandIsMemory(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintMemMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, INS_MemoryWriteSize(ins),
                IARG_END);
        }
        // free taint
        else if(INS_OperandIsImmediate(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintMemImm,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);   
        } else {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_END);
        }
        break;

    case XED_ICLASS_POP:
        //memory -> reg
        if(INS_OperandIsReg(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintRegMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_RegW(ins, OP_0),
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_END);
        }
        //memory -> mem
        else if(INS_OperandIsMemory(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)taintMemMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, INS_MemoryWriteSize(ins),
                IARG_END);
        }
        else{
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_END);
        }

        break;

    // arithmetic operation
    case XED_ICLASS_ADC:
    case XED_ICLASS_ADD:
    case XED_ICLASS_SBB:
    case XED_ICLASS_SUB:

    case XED_ICLASS_ADDSD:  // SSE2 指令集, 浮点数指令相加, 低 64 位 double 相加
    case XED_ICLASS_SUBSD:

    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_XOR:

    case XED_ICLASS_PAND:
    case XED_ICLASS_POR:
    case XED_ICLASS_PXOR:

        if(INS_MemoryOperandCount(ins) == 0){
            if(!INS_OperandIsImmediate(ins, OP_1)){
                //reg, reg
                if(ins_indx == XED_ICLASS_XOR){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceXORRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else if(ins_indx == XED_ICLASS_OR){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceORRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    if(REG_is_xmm_ymm_zmm(INS_OperandReg(ins, OP_0)) || REG_is_mm(INS_OperandReg(ins, OP_0))){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_UINT32, INS_OperandReg(ins, OP_0),
                            IARG_ADDRINT, 0,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_ADDRINT, 0,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    }
                    else
                    {
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_UINT32, INS_OperandReg(ins, OP_0),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    }
                }
            } 
            // reg, imm
            else{
                if(ins_indx == XED_ICLASS_AND){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceANDRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
            }
        }
        else{
            // reg, mem
            if(INS_OperandIsReg(ins, 0)){
                if(REG_is_xmm_ymm_zmm(INS_RegW(ins, OP_0)) || REG_is_mm(INS_RegW(ins, OP_0))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegMem,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_ADDRINT, 0,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);    
                }
                else{
                    if(ins_indx == XED_ICLASS_OR){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegMem,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_UINT32, INS_RegW(ins, OP_0),
                            IARG_REG_VALUE, INS_RegW(ins, OP_0),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);

                    } else{
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegMem,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_UINT32, INS_RegW(ins, OP_0),
                            IARG_REG_VALUE, INS_RegW(ins, OP_0),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    }
                }
            }
            // mem, reg
            else if(INS_OperandIsReg(ins, OP_1)){
                if(REG_is_xmm_ymm_zmm(INS_OperandReg(ins, OP_1)) || REG_is_mm(INS_OperandReg(ins, OP_1))){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_ADDRINT, 0,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else{
                    if(ins_indx == XED_ICLASS_OR){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceORMemReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    } else{
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_END);
                    }
                }
            } 
            // mem, imm
            else {
                if(ins_indx == XED_ICLASS_AND){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceANDMemImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);   
                }
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);   
                }
            }
        }


        break;

    case XED_ICLASS_INC:
    case XED_ICLASS_DEC:
    case XED_ICLASS_NOT:
        if(INS_OperandIsMemory(ins, OP_0)){

            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceArithMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYOP_EA, 0,
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);  
        }
        else if(INS_OperandIsReg(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceArithReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);

        }
        else {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_END);
        }

        break;
    
    case XED_ICLASS_DIV:
    case XED_ICLASS_IDIV:
        if(INS_OperandIsReg(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_1),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }
        else if(INS_OperandIsMemory(ins, OP_0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_RegW(ins, OP_0),
                IARG_REG_VALUE, INS_RegW(ins, OP_0),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }
        else {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_END);
        }

        break;

    case XED_ICLASS_MUL:
    case XED_ICLASS_IMUL:
        if(INS_OperandIsImplicit(ins, OP_1)){
            // OP_0 : Explicit Operand
            // OP_1 : Implicit Operand
            // OP_2 : Destination (Low)
            // OP_3 : Destination (High)
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_OperandReg(ins, OP_0),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_1)/8,
                    IARG_END);
            }
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_1)/8,
                    IARG_END);                
            }
        }
        else{
            if(INS_OperandCount(ins) == 4 && INS_OperandIsImmediate(ins, OP_2)){
                //reg, reg, imm
                if(INS_OperandIsReg(ins, OP_1)){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceMULRegRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_2),
                        IARG_END);
                }
                //reg, mem, imm
                else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceMULRegMemImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_2),
                        IARG_END);
                }
            }
            else if(INS_OperandCount(ins) == 3 && INS_OperandIsReg(ins, OP_0)){
                //reg, reg
                //reg + rax
                if(INS_OperandIsReg(ins, OP_1)){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                //reg, mem
                else if(INS_OperandIsMemory(ins, OP_1)){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_REG_VALUE, INS_RegW(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                //reg, imm
                else if(INS_OperandIsImmediate(ins, OP_1)){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_REG_VALUE, INS_RegW(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                } else{
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_END);
                }
            }
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_END);
            }
        }

        break;

    case XED_ICLASS_RCL:    // 把进位看作寄存器最高位一起参与循环左移
    case XED_ICLASS_RCR:
    case XED_ICLASS_ROL:    // 循环左移位
    case XED_ICLASS_ROR:
        if(INS_MemoryOperandCount(ins) == 0){
            if(!INS_OperandIsImmediate(ins, OP_1)){
                //reg, reg
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_OperandReg(ins, OP_0),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            } 
            // reg, imm
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithRegImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_REG_VALUE, INS_RegW(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                    IARG_END);
            }
        } else{
            // reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_0),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
            } 
            // mem, imm
            else if(INS_OperandIsImmediate(ins, OP_1)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                IARG_END);   
            }
        }

        break;
    
    case XED_ICLASS_SHL:
    case XED_ICLASS_SAR:
    case XED_ICLASS_SHR:
        if(INS_MemoryOperandCount(ins) == 0){
            if(!INS_OperandIsImmediate(ins, OP_1)){
                //reg, reg
                if(ins_indx == XED_ICLASS_SHL){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceSHLRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);
                }
                else if(ins_indx == XED_ICLASS_SAR || ins_indx == XED_ICLASS_SHR){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceSHRRegReg,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_OperandReg(ins, OP_0),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                        IARG_UINT32, INS_OperandReg(ins, OP_1),
                        IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_END);               
                }
            } 
            // reg, imm
            else{
                if(ins_indx == XED_ICLASS_SHL){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceSHLRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_REG_VALUE, INS_RegW(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
                else if(ins_indx == XED_ICLASS_SAR || ins_indx == XED_ICLASS_SHR){
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)traceSHRRegImm,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_UINT32, INS_OperandCount(ins),
                        IARG_UINT32, INS_RegW(ins, OP_0),
                        IARG_REG_VALUE, INS_RegW(ins, OP_0),
                        IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                        IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                }
            }
        }
        else{
            // reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceArithMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_0),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
            }
            // mem, imm
            else{
                if(INS_OperandIsImmediate(ins, OP_1)){
                    if(ins_indx == XED_ICLASS_SHL){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceSHLMemImm,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END);  
                    } 
                    else if(ins_indx == XED_ICLASS_SAR || ins_indx == XED_ICLASS_SHR){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceSHRMemImm,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                            IARG_UINT64, INS_OperandImmediate(ins, OP_1),
                        IARG_END); 
                    }
                }
                // mem, reg
                else if(INS_OperandIsReg(ins, OP_1)){
                    if(ins_indx == XED_ICLASS_SHL){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceSHLMemReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_MemoryReadSize(ins),
                        IARG_END); 
                    } 
                    else if(ins_indx == XED_ICLASS_SAR || ins_indx == XED_ICLASS_SHR){
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceSHRMemReg,
                            IARG_ADDRINT, INS_Address(ins),
                            IARG_PTR, new string(INS_Disassemble(ins)),
                            IARG_UINT32, INS_OperandCount(ins),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, INS_OperandReg(ins, OP_1),
                            IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                            IARG_UINT32, INS_MemoryReadSize(ins),
                        IARG_END); 
                    }
                }
            }
        }
    break;

    case XED_ICLASS_SHLD:
    case XED_ICLASS_SHRD:
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_END);
        break;

    case XED_ICLASS_MOV:
    case XED_ICLASS_MOVSX:  // move with sign extend, r16/32/64 <- r/m8/16
    case XED_ICLASS_MOVSXD: // r16/32/64 <- r/m32/64
    case XED_ICLASS_MOVZX:  // zero extend, r16/32/64 <- r/m8/16

    case XED_ICLASS_MOVD:   // xmm <- r/m32, MMX or SSE2 指令集
    case XED_ICLASS_MOVQ:   // xmm <- r/m64
    case XED_ICLASS_VMOVQ:  // AVX 指令集, 类似 movq
    case XED_ICLASS_VMOVD:

    case XED_ICLASS_MOVDQA: // 移动对齐 128 bits 数据: xmm <- xmm/m128
    case XED_ICLASS_MOVDQU: // 非对齐
    case XED_ICLASS_VMOVDQU:
    case XED_ICLASS_VMOVDQA:

    case XED_ICLASS_MOVAPS: // mov Aligned Packed Single floating, xmm <- xmm/m128
    case XED_ICLASS_MOVAPD:
    case XED_ICLASS_VMOVAPS:
    case XED_ICLASS_VMOVAPD:
        if (INS_MemoryOperandCount(ins) == 0) {
            // reg, reg
            if (!INS_OperandIsImmediate(ins, OP_1)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegR(ins, OP_0),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_ADDRINT, 0,    // unused
                    IARG_UINT32, INS_OperandWidth(ins, OP_1)/8,
                    IARG_END);
            }
            // reg, imm
            else {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            }
        }
        else {
            // reg, mem
            if (INS_OperandIsReg(ins, OP_0)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegMem,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_REG(ins, OP_0),
                    IARG_MEMORYREAD_SIZE,
                    IARG_END);
            }
            // mem, reg
            else if (INS_OperandIsReg(ins, OP_1)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_ADDRINT, 0,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END); 
            }
            // mem, imm
            else if (INS_OperandIsImmediate(ins, OP_1)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintMemImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            }
            else {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_END);
            }
        }
        break;

    /* conditional movs */
    /* TODO */ 
    case XED_ICLASS_CMOVB:
    case XED_ICLASS_CMOVBE:
    case XED_ICLASS_CMOVL:
    case XED_ICLASS_CMOVLE:
    case XED_ICLASS_CMOVNB:
    case XED_ICLASS_CMOVNBE:
    case XED_ICLASS_CMOVNL:
    case XED_ICLASS_CMOVNLE:
    case XED_ICLASS_CMOVNO:
    case XED_ICLASS_CMOVNP:
    case XED_ICLASS_CMOVNS:
    case XED_ICLASS_CMOVNZ:
    case XED_ICLASS_CMOVO:
    case XED_ICLASS_CMOVP:
    case XED_ICLASS_CMOVS:
    case XED_ICLASS_CMOVZ:
        if(INS_MemoryOperandCount(ins) == 0){
            if(!INS_OperandIsImmediate(ins, OP_1)){
                //reg, reg
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegR(ins, OP_0),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_REG_VALUE, INS_RegR(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_1)/8,
                    IARG_END);
            } 
            // reg, imm
            else{
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            }

        }

        else{
            // reg, mem
            if(INS_OperandIsReg(ins, OP_0)){
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintRegMem,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_UINT32, INS_MemoryReadSize(ins),
                    IARG_END);
            } 
            // mem, reg
            else if(INS_OperandIsReg(ins, OP_1)){
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            } 
            // mem, imm
            else if(INS_OperandIsImmediate(ins, OP_1)){
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintMemImm,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);   
            } 
            else{
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_END);
            }
        }

        break;

    case XED_ICLASS_XCHG:
        if(INS_MemoryOperandCount(ins) == 0){
        //reg reg
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceXCHGRegReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandReg(ins, OP_1),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }
        else{
            //reg mem
            if(INS_OperandIsReg(ins, OP_0)){                       
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceXCHGRegMem,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_OperandReg(ins, OP_0),        
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            }
            //mem reg
            else{
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceXCHGMemReg,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, INS_OperandReg(ins, OP_1),
                    IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
            }
        }

        break;

    case XED_ICLASS_CMPXCHG:
        if(INS_MemoryOperandCount(ins) == 0){
        //reg reg
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceCMPXCHGRegReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_CONTEXT,
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandReg(ins, OP_1),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }
        else{
        //mem reg
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceCMPXCHGMemReg,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_CONTEXT,
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, INS_OperandReg(ins, OP_1),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_1),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);
        }

        break;

    /* just untaint register */
    /* TODO */
    case XED_ICLASS_LEA:
        if (INS_OperandCount(ins) >= 2 && INS_OperandIsAddressGenerator(ins, OP_1)) {
            INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taint_lea_mem,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_CONTEXT,
                    IARG_REG(ins, OP_0),        // dst
                    IARG_BASEREG(ins, OP_1),
                    IARG_INDEXREG(ins, OP_1),
                    IARG_SCALE(ins, OP_1),
                    IARG_DISPLACEMENT(ins, OP_1),
                    IARG_UINT32, INS_Size(ins),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
        } else {
            INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)taintLEA,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_UINT32, INS_OperandCount(ins),
                    IARG_UINT32, INS_RegW(ins, OP_0),
                    IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                    IARG_END);
        }

        break;

    /* TODO */
    case XED_ICLASS_SETB:
    case XED_ICLASS_SETBE:
    case XED_ICLASS_SETL:
    case XED_ICLASS_SETLE:
    case XED_ICLASS_SETNB:
    case XED_ICLASS_SETNBE:
    case XED_ICLASS_SETNL:
    case XED_ICLASS_SETNLE:
    case XED_ICLASS_SETNO:
    case XED_ICLASS_SETNP:
    case XED_ICLASS_SETNS:
    case XED_ICLASS_SETNZ:
    case XED_ICLASS_SETO:
    case XED_ICLASS_SETP:
    case XED_ICLASS_SETS:
    case XED_ICLASS_SETZ:
        INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)traceUnsupport,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_END);
        break;

    case XED_ICLASS_BSWAP:
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceBSWAP,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, OP_0),
                IARG_REG_VALUE, INS_OperandReg(ins, OP_0),
                IARG_UINT32, INS_OperandWidth(ins, OP_0)/8,
                IARG_END);

        break;

    default:
        break;
    }
}
