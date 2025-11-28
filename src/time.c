#include "time.h"

uint64_t time_cache;

void increment_time_cache(uint64_t ms)
{
    time_cache += ms;
}

uint64_t get_time_cache()
{
    return time_cache;
}