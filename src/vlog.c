#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "vlog.h"

#define LOG_MODULE VLM_vlog

/* Saturating addition: overflow yields UINT_MAX. */
static inline unsigned int sat_add(unsigned int x, unsigned int y) {
    return x + y >= x ? x + y : UINT_MAX;
}

/* Saturating subtraction: underflow yields 0. */
static inline unsigned int sat_sub(unsigned int x, unsigned int y) {
    return x >= y ? x - y : 0;
}

/* Saturating multiplication: overflow yields UINT_MAX. */
static inline unsigned int sat_mul(unsigned int x, unsigned int y) {
    return (!y ? 0 : x <= UINT_MAX / y ? x * y : UINT_MAX);
}

/* Name for each logging level. */
static const char* level_names[VLL_N_LEVELS] = {
#define VLOG_LEVEL(NAME) #NAME,
    VLOG_LEVELS
#undef VLOG_LEVEL
};

/* Name for each logging module */
static const char* module_names[VLM_N_MODULES] = {
#define VLOG_MODULE(NAME) #NAME,
#include "vlog-modules.def"
#undef VLOG_MODULE
};

/* Information about each facility. */
struct facility {
    const char* name; /* Name. */
};
static struct facility facilities[VLF_N_FACILITIES] = {
#define VLOG_FACILITY(NAME) { #NAME },
    VLOG_FACILITIES
#undef VLOG_FACILITY
};

/* Current log levels. */
static int levels[VLM_N_MODULES][VLF_N_FACILITIES];

/* For fast checking whether we're logging anything for a given module and
 * level.*/
enum vlog_level min_vlog_levels[VLM_N_MODULES];

/* VLF_FILE configuration. */
static char* log_file_name;
static FILE* log_file;
static int log_file_max_size;

/* Searches the 'n_names' in 'names'.  Returns the index of a match for
 * 'target', or 'n_names' if no name matches. */
static size_t search_name_array(const char* target, const char** names, size_t n_names) {
    size_t i;

    for(i = 0; i < n_names; i++) {
        assert(names[i]);
        if(!strcasecmp(names[i], target)) {
            break;
        }
    }
    return i;
}

/* Returns the name for logging level 'level'. */
const char* vlog_get_level_name(enum vlog_level level) {
    assert(level < VLL_N_LEVELS);
    return level_names[level];
}

/* Returns the logging level with the given 'name', or VLL_N_LEVELS if 'name'
 * is not the name of a logging level. */
enum vlog_level vlog_get_level_val(const char* name) {
    return search_name_array(name, level_names, ARRAY_SIZE(level_names));
}

/* Returns the name for logging facility 'facility'. */
const char* vlog_get_facility_name(enum vlog_facility facility) {
    assert(facility < VLF_N_FACILITIES);
    return facilities[facility].name;
}

/* Returns the logging facility named 'name', or VLF_N_FACILITIES if 'name' is
 * not the name of a logging facility. */
enum vlog_facility vlog_get_facility_val(const char* name) {
    size_t i;

    for(i = 0; i < VLF_N_FACILITIES; i++) {
        if(!strcasecmp(facilities[i].name, name)) {
            break;
        }
    }
    return i;
}

/* Returns the name for logging module 'module'. */
const char* vlog_get_module_name(enum vlog_module module) {
    assert(module < VLM_N_MODULES);
    return module_names[module];
}

/* Returns the logging module named 'name', or VLM_N_MODULES if 'name' is not
 * the name of a logging module. */
enum vlog_module vlog_get_module_val(const char* name) {
    return search_name_array(name, module_names, ARRAY_SIZE(module_names));
}

/* Returns the current logging level for the given 'module' and 'facility'. */
enum vlog_level vlog_get_level(enum vlog_module module, enum vlog_facility facility) {
    assert(module < VLM_N_MODULES);
    assert(facility < VLF_N_FACILITIES);
    return levels[module][facility];
}

static void update_min_level(enum vlog_module module) {
    enum vlog_level min_level = VLL_EMER;
    enum vlog_facility facility;

    for(facility = 0; facility < VLF_N_FACILITIES; facility++) {
        if(log_file || facility != VLF_FILE) {
            min_level = MAX(min_level, levels[module][facility]);
        }
    }
    min_vlog_levels[module] = min_level;
}

static void set_facility_level(enum vlog_facility facility,
enum vlog_module module,
enum vlog_level level) {
    assert(facility >= 0 && facility < VLF_N_FACILITIES);
    assert(level < VLL_N_LEVELS);

    if(module == VLM_ANY_MODULE) {
        for(module = 0; module < VLM_N_MODULES; module++) {
            levels[module][facility] = level;
            update_min_level(module);
        }
    } else {
        levels[module][facility] = level;
        update_min_level(module);
    }
}

/* Sets the logging level for the given 'module' and 'facility' to 'level'. */
void vlog_set_levels(enum vlog_module module, enum vlog_facility facility, enum vlog_level level) {
    assert(facility < VLF_N_FACILITIES || facility == VLF_ANY_FACILITY);
    if(facility == VLF_ANY_FACILITY) {
        for(facility = 0; facility < VLF_N_FACILITIES; facility++) {
            set_facility_level(facility, module, level);
        }
    } else {
        set_facility_level(facility, module, level);
    }
}

/* Returns the name of the log file used by VLF_FILE, or a null pointer if no
 * log file has been set.  (A non-null return value does not assert that the
 * named log file is in use: if vlog_set_log_file() or vlog_reopen_log_file()
 * fails, it still sets the log file name.) */
const char* vlog_get_log_file(void) {
    return log_file_name;
}

/* Sets the name of the log file used by VLF_FILE to 'file_name', or to the
 * default file name if 'file_name' is null.  Returns 0 if successful,
 * otherwise a positive errno value. The maximum size of the log file is set to
 * 'max_size' bytes; if 'max_size' is 0, the log file is allowed to grow
 * without limit.  (A non-positive 'max_size' is treated as 0.) */
int vlog_set_log_file(const char* file_name, int max_size) {
    char* old_log_file_name;
    enum vlog_module module;
    int error;

    /* Close old log file. */
    if(log_file) {
        VLOG_INFO(LOG_MODULE, "closing log file");
        fclose(log_file);
        log_file = NULL;
    }

    /* Update log file name and free old name.  The ordering is important
     * because 'file_name' might be 'log_file_name' or some suffix of it. */
    old_log_file_name = log_file_name;
    log_file_name = strdup(file_name);
    free(old_log_file_name);
    file_name = NULL; /* Might have been freed. */

    /* Open new log file and update min_levels[] to reflect whether we actually
     * have a log_file. */
    log_file = fopen(log_file_name, "a");
    for(module = 0; module < VLM_N_MODULES; module++) {
        update_min_level(module);
    }

    /* Log success or failure. */
    if(!log_file) {
        VLOG_WARN(LOG_MODULE, "failed to open %s for logging: %s",
        log_file_name, strerror(errno));
        error = errno;
    } else {
        VLOG_INFO(LOG_MODULE, "opened log file %s with max size %d", log_file_name, max_size);
        log_file_max_size = max_size;
        error = 0;
    }

    return error;
}

/* Initializes the logging subsystem. */
void vlog_init(void) {
    vlog_set_levels(VLM_ANY_MODULE, VLF_ANY_FACILITY, VLL_INFO);
}

/* Closes the logging subsystem. */
void vlog_exit(void) {
    if(log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    if(log_file_name) {
        free(log_file_name);
        log_file_name = NULL;
    }
}

/* Returns true if a log message emitted for the given 'module' and 'level'
 * would cause some log output, false if that module and level are completely
 * disabled. */
bool vlog_is_enabled(enum vlog_module module, enum vlog_level level) {
    return min_vlog_levels[module] >= level;
}

/* Writes 'message' to the log at the given 'level' and as coming from the
 * given 'module'.
 *
 * Guaranteed to preserve errno. */
void vlog_valist(enum vlog_module module,
enum vlog_level level,
const char* file,
int line,
time_t now,
const char* message,
va_list args) {
    bool log_to_console = levels[module][VLF_CONSOLE] >= level;
    bool log_to_file = levels[module][VLF_FILE] >= level && log_file;

    if(log_to_console || log_to_file) {
        int save_errno = errno;
        struct tm time;
        char buf[VLOG_MSG_MAX_LEN] = { 0 };
        size_t off = 0;
        const char* module_name = vlog_get_module_name(module);
        const char* level_name = vlog_get_level_name(level);
        int fd;
        int file_size;

        localtime_r(&now, &time);

        off = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &time);
        off += snprintf(buf + off, sizeof(buf) - off,
        " %-5s %-5s %s:%d: ", level_name, module_name, file, line);
        off += vsnprintf(buf + off, sizeof(buf) - off, message, args);
        if(off >= sizeof(buf)) {
            off = sizeof(buf) - 1;
        }
        buf[off++] = '\n';
        buf[off] = '\0';

        if(log_to_console) {
            fputs(buf, stderr);
            fflush(stderr);
        }
        if(log_to_file) {
            if(log_file_max_size > 0) {
                fseek(log_file, 0L, SEEK_END);
                file_size = ftell(log_file);
                if(file_size > log_file_max_size) {
                    fd = fileno(log_file);
                    ftruncate(fd, 0);
                    rewind(log_file);
                }
            }

            fputs(buf, log_file);
            fflush(log_file);
        }

        errno = save_errno;
    }
}

void vlog(enum vlog_module module, enum vlog_level level, const char* file, int line, const char* message, ...) {
    va_list args;
    time_t now = time(NULL);
    va_start(args, message);
    vlog_valist(module, level, file, line, now, message, args);
    va_end(args);
}

void vlog_rate_limit(enum vlog_module module,
enum vlog_level level,
const char* file,
int line,
struct vlog_rate_limit* rl,
const char* message,
...) {
    va_list args;

    if(!vlog_is_enabled(module, level)) {
        return;
    }

    time_t now = time(NULL);

    if(rl->tokens < VLOG_MSG_TOKENS) {
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
        if(rl->tokens < VLOG_MSG_TOKENS) {
            if(!rl->n_dropped) {
                rl->first_dropped = now;
            }
            rl->n_dropped++;
            return;
        }
    }
    rl->tokens -= VLOG_MSG_TOKENS;

    va_start(args, message);
    vlog_valist(module, level, file, line, now, message, args);
    va_end(args);

    if(rl->n_dropped) {
        vlog(module, level, file, line,
        "Dropped %u messages in last %u seconds due to excessive rate",
        rl->n_dropped, (unsigned int)(now - rl->first_dropped));
        rl->n_dropped = 0;
    }
}