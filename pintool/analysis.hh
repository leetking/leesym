#ifndef ANALYSIS_HH__
#define ANALYSIS_HH__

#include "pin.H"

VOID Instruction(INS ins, VOID *v);

#define OP_0    0
#define OP_1    1
#define OP_2    2
#define OP_3    3

extern bool isTaintStart;

#endif // ANALYSIS_HH__
