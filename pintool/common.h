#include <assert.h>

#define UNREACHABLE() assert(!"BUG??? This path is unreachable")
#define BUG_ON(exp)   assert(!(exp))
#define IS_POWER_OF2(num)   (~(((num)-1) & (num)))
#define IS_ERG_SIZE(size)   IS_POWER_OF2(size)
