#ifndef __BYE_RATELIMIT_H__
#define __BYE_RATELIMIT_H__

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct rate_limit {
    unsigned int rate;
    unsigned int burst;

    unsigned int tokens;
    time_t last_fill;
    time_t first_dropped;
    unsigned int n_dropped;
};

void rate_limit_init(struct rate_limit* rl, unsigned int rate, unsigned int burst);
bool rate_limit_check(struct rate_limit* rl);

#endif