
#include "./kmemmanager.h"
#include "./loger.h"
#include "./kernel_symbol.h"
#include "./sys_call_info.h"


bool init_util()
{
    init_kmemmanger();
    init_loger();
    init_sys_call_table_info();
    return init_kernel_symbol();
}

bool release_util()
{
    release_loger();
    release_kmemmanger();
    return true;
}

int open_util()
{
    return 0;
}

int close_util()
{
    return 0;
}
