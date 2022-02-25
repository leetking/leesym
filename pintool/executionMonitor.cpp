/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2016 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
 *  This file contains an ISA-portable PIN tool for tracing system calls
 */

#include <stdio.h>
#include <list>
#include <iostream>
#include <fstream>
#include <iomanip>

#if !defined(TARGET_WINDOWS)
#include <sys/syscall.h>
#endif

#include "executionMonitor.hpp"
#include "instruction.hpp"
#include "syscall.hpp"
#include "instrument.hpp"
#include "analysis.hpp"
#include "trace.hpp"

using namespace std;

ofstream logfile;

VOID Fini(INT32 code, VOID *v)
{
    logfile.close();
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    printf("pin -t pintool/obj-xxx/executionMonitor.so -i <input-file> "
           "-o <output-file> -l <log-file> -- <cmd> [opts]\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    PIN_InitSymbols();

    string outputFileName;
    string logFileName;

    targetFileName = KnobTargetFile.Value();
    outputFileName = KnobOutputFile.Value();
    logFileName = KnobLogFile.Value();

    logfile.open(logFileName.c_str());
    trace.open(outputFileName.c_str());

    if(!strcmp("stdin_", KnobTargetFile.Value().c_str())){
        doStdin();
    }

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
