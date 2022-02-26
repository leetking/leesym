#include <cstdio>

#include <list>
#include <iostream>
#include <fstream>

#if !defined(TARGET_WINDOWS)
# include <sys/syscall.h>
#endif

// this file is from intel PIN
#include <iomanip>
#include "pin.H"

#include "executionMonitor.hpp"
#include "instruction.hpp"
#include "syscall.hpp"
#include "instrument.hpp"
#include "analysis.hpp"
#include "trace.hpp"

using namespace std;

KNOB<string> KnobTargetFile(KNOB_MODE_WRITEONCE,  "pintool",
                          "i", "__NO_SUCH_FILE__",
                          "input file to target binary");

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
                          "o", "__NO_SUCH_FILE__",
                          "output file stored trace infomation");

KNOB<string> KnobLogFile(KNOB_MODE_WRITEONCE,  "pintool",
                          "l", "__NO_SUCH_FILE__",
                          "logfile file");


ofstream logfile;

static
VOID Fini(INT32 code, VOID *v)
{
    logfile.close();
}

static
INT32 Usage()
{
    printf("pin -t pintool/obj-xxx/executionMonitor.so -i <input-file> "
           "-o <output-file> -l <log-file> -- <cmd> [opts]\n");
    return -1;
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
        return Usage();

    PIN_InitSymbols();

    string outputFileName;
    string logFileName;

    targetFileName = KnobTargetFile.Value();
    outputFileName = KnobOutputFile.Value();
    logFileName = KnobLogFile.Value();

    logfile.open(logFileName.c_str());
    trace.open(outputFileName.c_str());

    // Intel 汇编语法
    PIN_SetSyntaxIntel();
    // Syscall入口和出口：建立输入和内存/寄存器的关联
    PIN_AddSyscallEntryFunction(SyscallEntry, nullptr);
    PIN_AddSyscallExitFunction(SyscallExit, nullptr);

    // 核心插桩，指令级别插桩
    INS_AddInstrumentFunction(Instruction, nullptr);

    PIN_AddFiniFunction(Fini, nullptr);

    // Never returns
    PIN_StartProgram();

    return 0;
}
