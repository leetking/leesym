#include <assert.h>

#define UNREACHABLE() assert(!"BUG??? This path is unreachable")
#define BUG_ON(exp)   assert(!(exp))
