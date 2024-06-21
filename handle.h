
#ifndef DEBUG_TOOL_HANDLE_H
#define DEBUG_TOOL_HANDLE_H

#include <stdbool.h>

struct base_control{
    int type;
    int (*handle)(unsigned long param);
};

struct base_tool {
    char *tag;
    bool (*init)();
    bool (*release)();
    int (*open)();
    int (*close)();
    struct base_control *control;
};

bool do_init();
bool do_release();

#endif
