debugtool
=
You can use this tool to help debug.
# description
1. 这个工具用于记录程序调用linux系统接口。虽然其他程序也有这个功能，但为了能更自由操作，所以自己再写一个。
2. Hook的方法是修改syscall table的地址，实现拦截。
3. 工具还有其他一些功能，类似dump其他进出的内存、反汇编驱动特点地址的内存。
4. 编译后会有一个应用层执行程序和一个驱动。应用层程序控制驱动程序是否HOOK内核和其他功能。
5. 这个工具，只适用于arm64的系统。
# compile
`./build.sh`
## output:
1. kernel module: debug_tool.ko<br>
2. exe: exedebugtool/debugtool<br>
# install
## push to instance
`adb push ./debut_tool.ko /data/local/tmp/`<br>
`adb push ./debugtool /data/local/tmp/`<br>
## insmode module
`insmode ./debut_tool.ko`
# help 
openat<br>
&emsp;-f openat -t [0|1|2]                    0:enable, 1:disable, 2:disable all.<br>
openat usage:<br>
&emsp;-f openat -t [0|1] -s src -r dst        replace src to dst.<br>
&emsp;-f openat -t [0|1] -d hide              hide file.<br>
&emsp;-f openat -t [0|1] -c cmdline           echo file when touch.<br>
<br>
kprint:<br>
&emsp;-f kprint -s sym                        print kernel symbol.<br>
&emsp;-f kprint -a addr                       print kernel address,e.g. 0x010203.<br>
&emsp;-f kprint -t [xd]                       print hex or disassemble.<br>
&emsp;-f kprint -u [csdg]                     for -t x. print unit size.<br>
&emsp;-f kprint -l count/line                 count for -t x. line for -t d.<br>
kprint usage:<br>
&emsp;-f kprint -[s|a] ... -t [xd] -u [csdg] -l ...<br>

# add new function
## add function in exe
### 1:
`cp handle_openat.c handle_***.c`<br>
`cp handle_openat.h handle_***.h`<br>
replace "openat" to *** in handle_\*\*\*.*<br>
modify code in handle_\*\*\*.*<br>
### 2: add *** in  main.cpp
`#include "./handle_getdents64.h"`<br>
`+#include "./handle_***.h"`<br>
` `<br>
`#define DEVICE_NAME "/dev/debugtools"`<br>
` `<br>
`+ #define DEBUGTOOL_HELP OPENAT_HELP KPRINT_HELP NEWFSTATAT_HELP GETDENTS64_HELP ***_HELP`<br>
` `<br>
`struct handle_function{`<br>
`    char *function;`<br>
`    void (*handle)(int fd, int argc, char **argv);`<br>
`};`<br>
`struct handle_function do_functions[] = {`<br>
`    {"openat", handle_openat},`<br>
`    {"kprint", handle_kprint},`<br>
`    {"newfstatat", handle_newfstatat},`<br>
`    {"getdents64", handle_getdents64},`<br>
`+   {"***", handle_***},`<br>
`    {NULL, NULL}`<br>
`};`<br>
## add function in kernel
### 1:
`cp ./handle_device/openat ./handle_device/*** -r`<br>
replace "openat" to *** in *** dir<br>
modify code in *** dir<br>
### 2: add *** in handle.cpp
`#include "./handle_device/getdents64/getdents64.h"`<br>
`+ #include "./handle_device/getdents64/***.h"`<br>
` `<br>
`#define MODULE_TAG "debugtool:handle"`<br>
` `<br>
`#define GENERIC_TOOL(tag, name)                     \`<br>
`{                                                   \`<br>
`    #tag, init_##name, release_##name,              \`<br>
`    open_##name, close_##name, &controls_##name      \`<br>
`}`<br>
`struct base_tool g_tools[] = {`<br>
`    GENERIC_TOOL(tag_util, util),`<br>
`    GENERIC_TOOL(tag_openat, openat),`<br>
`    GENERIC_TOOL(tag_kprint, kprint),`<br>
`    GENERIC_TOOL(tag_newfstatat, newfstatat),`<br>
`    GENERIC_TOOL(tag_getdents64, getdents64),`<br>
`+    GENERIC_TOOL(tag_***, ***),`<br>
`    {NULL, NULL, NULL, NULL, NULL, NULL}`<br>
`};`<br>
