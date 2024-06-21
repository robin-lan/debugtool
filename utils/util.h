
#ifndef DEBUT_TOOL_UTIL_H
#define DEBUT_TOOL_UTIL_H

#include "../handle.h"

bool init_util();
bool release_util();
int open_util();
int close_util();

struct base_control controls_util = {
    0, NULL
};

#endif
