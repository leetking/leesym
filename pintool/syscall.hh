#ifndef SYSCALL_HH__
#define SYSCALL_HH__

#include <fstream>
#include <iostream>

#include "pin.H"

extern std::ofstream logfile;

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5);

// Print the return value of the system call
VOID SysAfter(ADDRINT ret);

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);

#endif // SYSCALL_HH__
