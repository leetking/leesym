#include <list>

#if !defined(TARGET_WINDOWS)
# include <sys/syscall.h>   // import syscall number
# include <unistd.h>        // import sbrk()
#endif

#include "syscall.hpp"
#include "instrument.hpp"
#include "trace.hpp"
#include "common.h"

UINT64 globalOffset;

bool isTargetFileOpen=false;
bool isTargetFileRead=false;
bool isLseekCalled = false;
bool isLlseekCalled = false;
bool isTargetFileMmap2 = false;
bool isTaintStart = false;
bool isLibcSO = false;

UINT64* llseekResult;
UINT64 taintMemoryStart;
UINT64 mmapSize;
UINT64 targetFileFd=0xFFFFFFFF;
string targetFileName;


namespace {
enum {
    SYSCALL_NONE = (unsigned)-1,
    INVALID_FD = -1,
};
unsigned syscall_number = SYSCALL_NONE;

struct {
    bool started = false;
    int target_fd = STDIN_FILENO;   // 默认从标准输入读
    UINT64 offset = 0;
} taint;

struct {
    char* fname;
    int flags;
} open_info;

struct {
    int fd = INVALID_FD;
    ADDRINT addr = 0;
    ADDRINT size = 0;
} read_info;

struct {
    int fd = INVALID_FD;
} close_info;

struct {
    ADDRINT heap_ptr = 0;
    ADDRINT new_heap_ptr = 0;
} brk_info;

struct {
    ADDRINT start = 0;
    size_t length = 0;
} munmap_info;
} // end namespace

static inline
bool string_equal(char const* str1, char const* str2)
{
    return strcmp(str1, str2) == 0;
}


/**
 * num: syscall no
 */
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
    syscall_number = num;
#if defined(TARGET_LINUX) && defined(TARGET_IA32)
    // On ia32 Linux, there are only 5 registers for passing system call arguments, 
    // but mmap needs 6. For mmap on ia32, the first argument to the system call 
    // is a pointer to an array of the 6 arguments
    if (num == SYS_mmap) {
        ADDRINT * mmapArgs = reinterpret_cast<ADDRINT *>(arg0);
        arg0 = mmapArgs[0];
        arg1 = mmapArgs[1];
        arg2 = mmapArgs[2];
        arg3 = mmapArgs[3];
        arg4 = mmapArgs[4];
        arg5 = mmapArgs[5];
    }
#endif

    switch (syscall_number) {
    case __NR_brk:
        // 这里调用 brk 系统调用会导致无限递归
        brk_info.new_heap_ptr = arg0;
        //printf("Into __NR_brk %d %p %lx\n", syscall_number, brk_info.new_heap_ptr, arg0);
        break;

    case __NR_munmap:
        munmap_info.start = arg0;
        munmap_info.length = arg1;
        break;

    // 类似于 open, 打开相对于文件夹 at fd 下的文件
    case __NR_openat:
        logfile << "[openat]\tat fd: " << arg0
            << " fname: " << (arg1? (char*)arg1: "(null)")
            << " flags: " << hex << arg2 << endl;
        arg0 = arg1;
        arg1 = arg2;
    case __NR_open:
        logfile << "[open]\t\t" << "fname: " << (arg0? (char*)arg0: "(null)") << " ";
        logfile << hex << "flags: " << arg1 << endl;
        open_info.fname = (char*)arg0;
        open_info.flags = arg1;
        break;

    case __NR_close:
        logfile << "[close]\t\tfd: " << arg0 << endl;
        close_info.fd = arg0;
        break;

    // read(fd, addr, size)
    case __NR_read:
        logfile << "[read]\t\tfd: " << arg0
            << " addr: " << hex << arg1
            << " size: " << dec << arg2 << endl;
        read_info.fd = arg0;
        read_info.addr = arg1;
        read_info.size = arg2;
        break;

    case __NR_lseek:
        logfile << hex << "[lseek]\t\tfd: " << arg0 << " offset: " << arg1 << " whence: " << arg2 << endl;
        break;
    } // switch (syscall_number)

    if(num == __NR_lseek) {
        logfile << hex << "[LSEEK FILE]\t\tfd: " << arg0 << " offset: " << arg1 << " whence: " << arg2 << endl;

        if(arg0 == targetFileFd){
            isLseekCalled = true;
        }

    // TODO 140 是什么系统调用, llseek, 为何不写 __NR_llseek
    // TODO 为何要直接写 __NR_lseek 而不是 SYS_lseek 呢
    } else if(num == 140){
        logfile << hex << "[LLSEEK FILE]\t\tfd: " << arg0 << " offseth: " << arg1 << " offsetl: " << arg2 << " result: " << arg3 <<" whence: " << arg4 << endl;

        if(arg0 == targetFileFd) {
            llseekResult = (UINT64*)arg3;
            isLlseekCalled = true;
        }

    }
    // TODO mmap 和 mmap2 的区别
    else if (num == __NR_mmap){
        logfile << hex << "[MMAP]\t\taddr: " << arg0 << " length: " << arg1 << " prot: " << arg2 << " flags: " << arg3 <<" fd: " << arg4 << " offset: " << arg5 << endl;
    }
#if defined(TARGET_LINUX) && defined(TARGET_IA32)
    else if (num == __NR_mmap2){
        logfile << hex << "[MMAP2]\t\taddr: " << arg0 << " length: " << arg1 << " prot: " << arg2 << " flags: " << arg3 <<" fd: " << arg4 << " pgoffset: " << arg5 << endl;
        if (arg4 == targetFileFd && arg4 != 0xFFFFFFFF) {
            isTargetFileMmap2 = true;
            mmapSize = arg1;
            isTaintStart = true;
        }
    }
#endif
}

#define syscall_failed(ret) (((ADDRINT)-1) == (ret))

VOID SysAfter(ADDRINT ret)
{
    UINT64 size;

    switch (syscall_number) {
    case __NR_brk:
        if (syscall_failed(ret))
            break;
        // 减少内存
        if (brk_info.new_heap_ptr < brk_info.heap_ptr) {
            removeTaintBlock(brk_info.new_heap_ptr, brk_info.heap_ptr - brk_info.new_heap_ptr);
            UINT64 heap_ptr = brk_info.heap_ptr;
            UINT64 new_heap_ptr = brk_info.new_heap_ptr;
            logfile << hex << "[brk]\t\tremove from: " << new_heap_ptr << " to: " << heap_ptr << endl;
        }
        brk_info.heap_ptr = brk_info.new_heap_ptr;
        brk_info.new_heap_ptr = 0;
        break;

    case __NR_munmap:
        if (syscall_failed(ret))
            break;
        removeTaintBlock(munmap_info.start, munmap_info.length);
        logfile << hex << "[munmap]\t\tremove from: " << munmap_info.start << " len: " << munmap_info.length << endl;
        munmap_info.start = munmap_info.length = 0;
        break;

    case __NR_openat:
        if (syscall_failed(ret))
            break;
        logfile << "[openat]\topened fd: " << ret << endl;
    case __NR_open:
        if (syscall_failed(ret))
            break;
        logfile << "[open]\t\topened fd: " << ret << endl;
        // 已经开始污点分析了
        if (taint.started)
            break;
        // 打开目标程序读取的文件
        if (string_equal(open_info.fname, targetFileName.c_str())) {
            if (open_info.flags == O_RDONLY || open_info.flags == O_RDWR) {
                logfile << "[TAINT] open input file at " << ret << endl;
                taint.target_fd = ret;
            }
        }
        open_info.fname = nullptr;
        open_info.flags = 0x0;
        break;

    case __NR_read:
        if (syscall_failed(ret))
            break;
        if (read_info.fd != taint.target_fd)
            break;
        if (!taint.started) {
            logfile << "BEGIN TAINT!!" << endl;
            taint.started = true;
            isTaintStart = true;
        }
        size = ret;
        for (UINT64 i = 0; i < size; ++i)
            addTaintByte(read_info.addr + i, taint.offset++);
        logfile << "[TAINT]\t\taddr: " << hex << read_info.addr
            << " size: " << dec << ret
            << " offset: " << taint.offset - size << endl;
        read_info.fd = INVALID_FD;
        read_info.addr = 0x0;
        read_info.size = 0;
        break;

    case __NR_close:
        if (syscall_failed(ret))
            break;
        if (taint.target_fd == close_info.fd) {
            logfile << "[TAINT]\tClose input file fd " << taint.target_fd << endl;
            taint.target_fd = STDIN_FILENO;
        }
        close_info.fd = INVALID_FD;
        break;

    case __NR_mmap:
        break;

    case SYSCALL_NONE:
        UNREACHABLE();
        break;
    }
    syscall_number = SYSCALL_NONE;

    if (isLseekCalled == true) {
        isLseekCalled = false;
        globalOffset = ret;

        logfile << "[LSEEK] result: " << llseekResult << endl;
    }

    if(isLlseekCalled == true){
        isLlseekCalled = false;
        globalOffset = *llseekResult;

        logfile << "[LLSEEK] result: " << *llseekResult << endl;
    }

    // mmap2 内存映射方式读取
    if(isTargetFileMmap2){
        isTargetFileMmap2 = false;

        if(ret != 0xFFFFFFFF){
            UINT64 mmapResult = ret;

            for (UINT64 i = 0; i < mmapSize; i++){
                addTaintByte(mmapResult + i, i);
            }

            logfile << "[TAINT]\t\t\t0x" << mmapSize << " bytes tainted from ";
            logfile << hex << "0x" << mmapResult << " to 0x" << mmapResult+mmapSize << " (via mmap2)" << endl;
        }
    }
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysAfter(PIN_GetSyscallReturn(ctxt, std));
}

void doStdin()
{
    targetFileFd = 0;
    globalOffset = 0;
}
