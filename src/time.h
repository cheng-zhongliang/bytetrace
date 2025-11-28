#ifndef __BYE_TIME_H__
#define __BYE_TIME_H__

#include <stdint.h>

void increment_time_cache(uint64_t ms);
uint64_t get_time_cache();

#endif