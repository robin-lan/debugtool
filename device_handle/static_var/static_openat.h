
char *enoent_files[1] = {
    NULL
};

char *eacces_files[24] = {
    "/proc/bus/pci/devices",
    "/sys/class/net/lo/type",
    "/dev/__properties__",
    "/sys/block/loop0/loop/backing_file",
    "/sys/block/loop1/loop/backing_file",
    "/sys/block/loop2/loop/backing_file",
    "/sys/block/loop3/loop/backing_file",
    "/sys/block/loop4/loop/backing_file",
    "/sys/block/loop5/loop/backing_file",
    "/sys/block/loop6/loop/backing_file",
    "/sys/block/loop7/loop/backing_file",
    "/sys/block/loop8/loop/backing_file",
    "/sys/block/loop9/loop/backing_file",
    "/sys/block/loop10/loop/backing_file",
    "/sys/block/loop11/loop/backing_file",
    "/sys/block/loop12/loop/backing_file",
    "/sys/block/loop13/loop/backing_file",
    "/sys/block/loop14/loop/backing_file",
    "/sys/block/loop15/loop/backing_file",
    "/sys/block/loop16/loop/backing_file",
    "/sys/block/loop17/loop/backing_file",
    "/sys/block/loop18/loop/backing_file",
    "/sys/block/loop19/loop/backing_file",
    NULL
};

struct replace2_file {
    const char *from;
    const char *to;
};

struct replace2_file replace2_files[6] = {
    {"/proc/self/mounts",       "/oem/shared/mounts"},
    {"/proc/self/mountinfo",    "/oem/shared/mountinfo"},
    {"/proc/modules",           "/oem/shared/modules"},
    {"/sys/fs/selinux/enforce", "/oem/shared/enforce"},
    {"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", "/oem/shared/cpuinfo_max_freq"},
    {NULL, NULL}
};
