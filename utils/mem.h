#ifndef __MEM_20210117__
#define __MEM_20210117__

#include <stdlib.h>
#include "log.h"


#ifndef alloc_die
#define alloc_die(size)	(calloc(1, size) ?: (exit(1), (void*)NULL))
#endif


#endif