

MOD_NAME := debug_tool
obj-m += ${MOD_NAME}.o
debug_tool-y := ./device_handler.o                          \
                ./utils/kernel_symbol.o                     \
                ./utils/process.o                           \
                ./utils/kmemmanager.o                       \
                ./utils/kmem.o                              \
                ./utils/kmemprint.o                         \
                ./utils/util.o                              \
                ./utils/hook_systable.o                     \
                ./utils/userfile.o                          \
                ./utils/loger.o                             \
                ./utils/dump_user_content.o                 \
                ./utils/sys_call_info.o                     \
                ./device_handle/filter_process.o            \
                ./device_handle/echo_process/echo_process.o \
                ./device_handle/echo_process/cmd_echo_process.o \
                ./device_handle/openat/cmd_openat.o         \
                ./device_handle/openat/openat.o             \
                ./device_handle/read/read.o                 \
                ./device_handle/mmap/mmap.o                 \
                ./device_handle/uname/uname.o               \
                ./device_handle/ptrace/ptrace.o             \
                ./device_handle/hooksyscallroot/hooksyscallroot.o    \
                ./device_handle/getdents64/cmd_getdents64.o \
                ./device_handle/getdents64/getdents64.o     \
                ./device_handle/kprint/cmd_kprint.o         \
                ./device_handle/kprint/kprint.o             \
                ./device_handle/statfs/cmd_statfs.o         \
                ./device_handle/statfs/statfs.o             \
                ./device_handle/faccessat/faccessat.o       \
                ./device_handle/faccessat/cmd_faccessat.o   \
                ./device_handle/stat/newfstatat/cmd_newfstatat.o \
                ./device_handle/stat/fstat/fstat.o          \
                ./device_handle/stat/newfstatat/newfstatat.o     \
                ./device_handle/dump_loger/cmd_dump_loger.o \
                ./device_handle/dump_loger/dump_loger.o     \
                ./device_handle/dump_memory/cmd_dump_memory.o \
                ./device_handle/dump_memory/dump_memory.o     \
                ./handle.o                                  \
                main.o


#KERNELDIR := /home/lanliqiang/worksrc/berlin/linux-headers/linux-headers-5.11.0-1022-aws
KERNELDIR := /home/lanliqiang/worksrc/berlin/android13-aws-header/linux-headers-5.11.0-1022-aws
#KERNELDIR := /mnt/sda3/buildroot/buildroot-2023.11-rc2/output/build/linux-5.11.20

PWD := $(shell pwd)

KBUILD_CFLAGS := -Werror -Wfatal-errors -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-pointer-sign -O1
.PHONY: ${MOD_NAME}.ko
${MOD_NAME}.ko:
	@echo building modules
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf $(shell find ./exedebugtool/capstone/ -name '*.o')
	rm -rf $(shell find ./exedebugtool/ -name '*.o')
	rm -rf $(shell find ./device_handle/ -name '*.o')
	rm -rf $(shell find ./utils/ -name '*.o')
	rm -rf $(shell find ./ -name '*.o')
	rm -rf $(shell find ./ -name  "*.o.cmd")
	rm -rf $(shell find ./ -name "*.cmd")
	rm -rf ./.tmp_versions *.mod.c *.mod *.depend *.ko *.symvers *.order  ./exedebugtool/debugtool
