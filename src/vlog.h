#ifndef __VLOG_H__
#define __VLOG_H__

#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

#define ARRAY_SIZE(ARRAY) (sizeof ARRAY / sizeof *ARRAY)

/* Logging importance levels. */
#define VLOG_LEVELS  \
    VLOG_LEVEL(EMER) \
    VLOG_LEVEL(ERR)  \
    VLOG_LEVEL(WARN) \
    VLOG_LEVEL(INFO) \
    VLOG_LEVEL(DBG)
enum vlog_level {
#define VLOG_LEVEL(NAME) VLL_##NAME,
    VLOG_LEVELS
#undef VLOG_LEVEL
    VLL_N_LEVELS
};

const char* vlog_get_level_name(enum vlog_level);
enum vlog_level vlog_get_level_val(const char* name);

/* Facilities that we can log to. */
#define VLOG_FACILITIES    \
    VLOG_FACILITY(CONSOLE) \
    VLOG_FACILITY(FILE)
enum vlog_facility {
#define VLOG_FACILITY(NAME) VLF_##NAME,
    VLOG_FACILITIES
#undef VLOG_FACILITY
    VLF_N_FACILITIES,
    VLF_ANY_FACILITY = -1
};

const char* vlog_get_facility_name(enum vlog_facility);
enum vlog_facility vlog_get_facility_val(const char* name);

/* VLM_ constant for each vlog module. */
enum vlog_module {
#define VLOG_MODULE(NAME) VLM_##NAME,
#include "vlog-modules.def"
    VLM_N_MODULES,
    VLM_ANY_MODULE = -1
#undef VLOG_MODULE
};

const char* vlog_get_module_name(enum vlog_module);
enum vlog_module vlog_get_module_val(const char* name);

/* Rate-limiter for log messages. */
struct vlog_rate_limit {
    /* Configuration settings. */
    unsigned int rate;  /* Tokens per second. */
    unsigned int burst; /* Max cumulative tokens credit. */

    /* Current status. */
    unsigned int tokens;    /* Current number of tokens. */
    time_t last_fill;       /* Last time tokens added. */
    time_t first_dropped;   /* Time first message was dropped. */
    unsigned int n_dropped; /* Number of messages dropped. */
};

/* Number of tokens to emit a message.  We add 'rate' tokens per second, which
 * is 60 times the unit used for 'rate', thus 60 tokens are required to emit
 * one message. */
#define VLOG_MSG_TOKENS 60

/* Initializer for a struct vlog_rate_limit, to set up a maximum rate of RATE
 * messages per minute and a maximum burst size of BURST messages. */
#define VLOG_RATE_LIMIT_INIT(RATE, BURST)                                      \
    {                                                                          \
        RATE,                                                       /* rate */ \
        (MIN(BURST, UINT_MAX / VLOG_MSG_TOKENS) * VLOG_MSG_TOKENS), /* burst */                                                                            \
        0, /* tokens */                                                        \
        0, /* last_fill */                                                     \
        0, /* first_dropped */                                                 \
        0, /* n_dropped */                                                     \
    }

/* Configuring how each module logs messages. */
enum vlog_level vlog_get_level(enum vlog_module, enum vlog_facility);
void vlog_set_levels(enum vlog_module, enum vlog_facility, enum vlog_level);
bool vlog_is_enabled(enum vlog_module, enum vlog_level);

/* Configuring log facilities. */
const char* vlog_get_log_file(void);
int vlog_set_log_file(const char* file_name, int max_size);

/* Maximum length of a single log message, including the terminating null
 * character.  Longer messages will be truncated. */
#define VLOG_MSG_MAX_LEN 2048

/* Function for actual logging. */
void vlog_init(void);
void vlog_exit(void);
void vlog(enum vlog_module, enum vlog_level, const char* file, int line, const char* format, ...)
__attribute__((format(printf, 5, 6)));
void vlog_rate_limit(enum vlog_module,
enum vlog_level,
const char* file,
int line,
struct vlog_rate_limit*,
const char*,
...) __attribute__((format(printf, 6, 7)));

/* Convenience macros.
 * Guaranteed to preserve errno.
 */
#define VLOG_EMER(MODULE, ...) \
    VLOG(MODULE, VLL_EMER, __FILE__, __LINE__, __VA_ARGS__)
#define VLOG_ERR(MODULE, ...) \
    VLOG(MODULE, VLL_ERR, __FILE__, __LINE__, __VA_ARGS__)
#define VLOG_WARN(MODULE, ...) \
    VLOG(MODULE, VLL_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define VLOG_INFO(MODULE, ...) \
    VLOG(MODULE, VLL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define VLOG_DBG(MODULE, ...) \
    VLOG(MODULE, VLL_DBG, __FILE__, __LINE__, __VA_ARGS__)

/* More convenience macros, for testing whether a given level is enabled in
 * MODULE.  When constructing a log message is expensive, this enables it
 * to be skipped. */
#define VLOG_IS_EMER_ENABLED(MODULE) true
#define VLOG_IS_ERR_ENABLED(MODULE) vlog_is_enabled(MODULE, VLL_EMER)
#define VLOG_IS_WARN_ENABLED(MODULE) vlog_is_enabled(MODULE, VLL_WARN)
#define VLOG_IS_INFO_ENABLED(MODULE) vlog_is_enabled(MODULE, VLL_INFO)
#define VLOG_IS_DBG_ENABLED(MODULE) vlog_is_enabled(MODULE, VLL_DBG)

/* Convenience macros.
 * Guaranteed to preserve errno.
 */
#define VLOG_ERR_RL(MODULE, RL, ...) \
    VLOG_RL(MODULE, RL, VLL_ERR, __FILE__, __LINE__, __VA_ARGS__)
#define VLOG_WARN_RL(MODULE, RL, ...) \
    VLOG_RL(MODULE, RL, VLL_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define VLOG_INFO_RL(MODULE, RL, ...) \
    VLOG_RL(MODULE, RL, VLL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define VLOG_DBG_RL(MODULE, RL, ...) \
    VLOG_RL(MODULE, RL, VLL_DBG, __FILE__, __LINE__, __VA_ARGS__)

/* Implementation details. */
#define VLOG(MODULE, LEVEL, _FILE, LINE, ...)              \
    do {                                                   \
        if(min_vlog_levels[MODULE] >= LEVEL) {             \
            vlog(MODULE, LEVEL, _FILE, LINE, __VA_ARGS__); \
        }                                                  \
    } while(0)
#define VLOG_RL(MODULE, RL, LEVEL, _FILE, LINE, ...)                      \
    do {                                                                  \
        if(min_vlog_levels[MODULE] >= LEVEL) {                            \
            vlog_rate_limit(MODULE, LEVEL, _FILE, LINE, RL, __VA_ARGS__); \
        }                                                                 \
    } while(0)
extern enum vlog_level min_vlog_levels[VLM_N_MODULES];

#endif