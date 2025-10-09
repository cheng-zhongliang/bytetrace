#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "dropreason.h"

#define REASON_MAX_COUNT 256
#define REASON_MAX_LEN 32

static char drop_reasons[REASON_MAX_COUNT][REASON_MAX_LEN] = {};
static int drop_reason_max;
static bool drop_reason_inited = false;

bool fsearch(FILE* f, char* target) {
    char tmp[128];

    while(fscanf(f, "%s", tmp) == 1) {
        if(strstr(tmp, target))
            return true;
    }
    return false;
}

static int parse_reason_enum() {
    char name[REASON_MAX_LEN];
    int index = 0;
    FILE* f;

    f = fopen("/sys/kernel/debug/tracing/events/skb/kfree_skb/format", "r");

    if(!f || !fsearch(f, "__print_symbolic")) {
        if(f)
            fclose(f);
        return -1;
    }

    while(true) {
        if(!fsearch(f, "{") || fscanf(f, "%d, \"%31[A-Z_0-9]", &index, name) != 2)
            break;
        strcpy(drop_reasons[index], name);
    }
    drop_reason_max = index;
    drop_reason_inited = true;

    fclose(f);
    return 0;
}

char* get_drop_reason(int index) {
    if(!drop_reason_inited && parse_reason_enum())
        return NULL;
    if(index <= 0 || index > drop_reason_max)
        return NULL;

    return drop_reasons[index];
}
