#include <limits.h>
#include <stdbool.h>

#include "log.h"
#include "ratelimit.h"
#include "time.h"

#define BYE_MSG_TOKENS 60

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

static inline unsigned int sat_add(unsigned int x, unsigned int y)
{
    return x + y >= x ? x + y : UINT_MAX;
}

static inline unsigned int sat_mul(unsigned int x, unsigned int y)
{
    return (!y ? 0 : x <= UINT_MAX / y ? x * y : UINT_MAX);
}

void rate_limit_init(struct rate_limit* rl, unsigned int rate, unsigned int burst)
{
    rl->rate = rate;
    rl->burst = MIN(burst, UINT_MAX / BYE_MSG_TOKENS) * BYE_MSG_TOKENS;
    rl->tokens = 0;
    rl->last_fill = 0;
    rl->first_dropped = 0;
    rl->n_dropped = 0;
}

bool rate_limit_check(struct rate_limit* rl)
{
    unsigned int now;

    if(rl->rate == 0) {
        return true;
    }

    now = (unsigned int)(get_time_cache() / 1000);

    if(rl->tokens < BYE_MSG_TOKENS) {
        if(rl->last_fill > now) {
            /* Last filled in the future?  Time must have gone backward, or
             * 'rl' has not been used before. */
            rl->tokens = rl->burst;
        } else if(rl->last_fill < now) {
            unsigned int add = sat_mul(rl->rate, now - rl->last_fill);
            unsigned int tokens = sat_add(rl->tokens, add);
            rl->tokens = MIN(tokens, rl->burst);
            rl->last_fill = now;
        }
        if(rl->tokens < BYE_MSG_TOKENS) {
            if(!rl->n_dropped) {
                rl->first_dropped = now;
            }
            rl->n_dropped++;
            return false;
        }
    }
    rl->tokens -= BYE_MSG_TOKENS;

    if(rl->n_dropped) {
        log_trace(
        "Dropped %u messages in last %u seconds due to excessive rate",
        rl->n_dropped, (unsigned int)(now - rl->first_dropped));
        rl->n_dropped = 0;
    }

    return true;
}