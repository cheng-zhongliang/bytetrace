#ifndef __LOOKUP_KAS_H__
#define __LOOKUP_KAS_H__

#include <asm/types.h>
#include <stdlib.h>

struct loc_result {
    const char* symbol;
    __u64 offset;
};

int lookup_kas_sym(void* pc, struct loc_result* location);

#endif