#ifndef __BYE_PROTO_H__
#define __BYE_PROTO_H__

#include <stdint.h>

extern char* l4_proto_names[];

static inline char* i2l4(uint8_t num) {
    return l4_proto_names[num];
}

int proto2i(char* proto, int* dest);

#endif