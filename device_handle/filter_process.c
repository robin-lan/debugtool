

#include "../utils/process.h"
#include "../utils/kmemmanager.h"
#include "../exedebugtool/main.h"


#define DO_FILETER

#ifdef DO_FILETER
static char *process[2] = {
    "nmcore",
    NULL
};
//    "com.netmarble.tog",
//    "com.takeonecompany.nctz",
//    "com.google.android.gms",
//    "com.android.vending",

static char *thread[3] = {
    "binder",
    "IntentService",
    NULL
};
#endif

bool filter_process()
{
#ifdef DO_FILETER
    char *cmdline = dt_kmalloc_fast_path();
    if (NULL == cmdline) {
        return false;
    }
    get_cmdline(current, cmdline, dt_get_kmalloc_fast_size());
    for (int i = 0; i < sizeof(process) / sizeof(char *); i++) {
        if (NULL == process[i]) {
            break;
        }
        if (strstr(cmdline, process[i])) {
            dt_kfree_fast_path(cmdline);
            return true;
        }
    }

    dt_kfree_fast_path(cmdline);
    return false;
#else
    return true;
#endif
}


bool filter_thread()
{
    return true;
#ifdef DO_FILETER
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    get_task_comm(comm, current);
    for (int i = 0; i < sizeof(thread) / sizeof(char *); i++) {
        if (NULL == thread[i]) {
            break;
        }
        if (strstr(comm, thread[i])) {
            return true;
        }
    }

    return false;
#else
    return true;
#endif
}
