
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include "main.h"
#include "./handle_openat.h"
#include "./handle_newfstatat.h"
#include "./handle_getdents64.h"

static const char *opt_param = "t:a:d:";

static const struct option long_option[] = {
    {"type", required_argument, NULL, 't'},
    {"src", required_argument, NULL, 'a'},
    {"des", required_argument, NULL, 'd'},
    {0, 0, 0, 0}
};

extern int optind, ipterr, optopt;

void nop_operation(char *path)
{
    if (strlen(path) == 1) {
        return;
    }
    if ('/' == path[strlen(path) - 1]) {
        path[strlen(path) - 1] = 0;
    }
}

void handle_file(int fd, int type, char *src, char *native_src, char *src_parent, char *des, char *des_parent)
{
    char isrc[MAX_PATH_LEN] = {0};
    char inative_src[MAX_PATH_LEN] = {0};
    char isrc_parent[MAX_PATH_LEN] = {0};
    char ides[MAX_PATH_LEN] = {0};
    char ides_parent[MAX_PATH_LEN] = {0};
    if (strlen(src) > MAX_PATH_LEN || strlen(native_src) > MAX_PATH_LEN
            || strlen(src_parent) > MAX_PATH_LEN || strlen(des) > MAX_PATH_LEN
            || strlen(des_parent) > MAX_PATH_LEN) {
        printf("path is larger then buffer. error.\n");
        return;
    }
    snprintf(isrc, sizeof(isrc), "%s", src);
    snprintf(inative_src, sizeof(inative_src), "%s", inative_src);
    snprintf(isrc_parent, sizeof(isrc_parent), "%s", isrc_parent);
    snprintf(ides, sizeof(ides), "%s", ides);
    snprintf(ides_parent, sizeof(ides_parent), "%s", des_parent);

    nop_operation(isrc);
    nop_operation(inative_src);
    nop_operation(isrc_parent);
    nop_operation(ides);
    nop_operation(ides_parent);

    if (0 == type) {
        handle_openat_(fd, 0, des, src, NULL);
        handle_newfstatat_(fd, 0, des, src);
        handle_getdents64_(fd, 0, native_src, NULL, des_parent, src_parent);
    }
    if (1 == type) {
        handle_openat_(fd, 1, des, src, NULL);
        handle_newfstatat_(fd, 1, des, src);
        handle_getdents64_(fd, 1, native_src, NULL, des_parent, src_parent);
    }
}

static void trave_dir(int fd, int type, char* path, char *des_path)
{
    DIR *d = NULL;
    struct dirent *dp = NULL;
    struct stat st;    
    char p[MAX_PATH_LEN + 2] = {0};
    char pd[MAX_PATH_LEN + 2] = {0};
    
    if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        printf("invalid path: %s\n", path);
        return;
    }

    if(!(d = opendir(path))) {
        printf("opendir[%s] error: %m\n", path);
        return;
    }

    while((dp = readdir(d)) != NULL) {
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2)))
            continue;

        snprintf(p, sizeof(p) - 1, "%s/%s", path, dp->d_name);
        snprintf(pd, sizeof(p) - 1, "%s/%s", des_path, dp->d_name);
        stat(p, &st);
        if(!S_ISDIR(st.st_mode)) {
            handle_file(fd, type, p, dp->d_name, path, pd, des_path);
        } else {
            handle_file(fd, type, p, dp->d_name, path, pd, des_path);
            trave_dir(fd, type, p, pd);
        }
    }
    closedir(d);

    return;
}

void handle_adddir_(int fd, int type, char *abs_src_dir, char *abs_des_dir)
{
    char iabs_src_dir[MAX_PATH_LEN] = {0};
    char iabs_des_dir[MAX_PATH_LEN] = {0};
    if (strlen(abs_src_dir) > MAX_PATH_LEN || strlen(abs_des_dir) > MAX_PATH_LEN) {
        printf("path is larger then buffer. error.\n");
        return;
    }
    snprintf(iabs_src_dir, sizeof(iabs_src_dir), "%s", abs_src_dir);
    snprintf(iabs_des_dir, sizeof(iabs_des_dir), "%s", abs_des_dir);

    nop_operation(iabs_src_dir);
    nop_operation(iabs_des_dir);

    trave_dir(fd, type, iabs_src_dir, iabs_des_dir);
}

void handle_adddir(int fd, int argc, char **argv)
{
    int type = -1;
    char  *ret;
    char src_dir[0x200] = {0};
    char des_dir[0x200] = {0};
    char abs_src_dir[0x200] = {0};
    char abs_des_dir[0x200] = {0};
    int opt;
    int long_index = 0;
    optind = 1;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if (NULL == optarg) {
            continue;
        }
        switch (opt) {
            case 't':
                type = atoi(optarg);
                break;
            case 'a':
                strcpy(src_dir, optarg);
                break;
            case 'd':
                strcpy(des_dir, optarg);
                break;
            default:
                continue;
        }
    }
    if (2 == type) {
        handle_openat_(fd, 2, NULL, NULL, NULL);
        handle_newfstatat_(fd, 2, NULL, NULL);
        handle_getdents64_(fd, 2, NULL, NULL, NULL, NULL);
        return;
    }
    if (0 == strlen(src_dir) || 0 == strlen(des_dir) || -1 == type) {
        printf("src or des is null or type is unset. error.\n");
        return;
    }

    ret = realpath(src_dir, abs_src_dir);
    if (NULL == ret) {
        printf("readlink %s error.%s\n", src_dir, strerror(errno));
        return;
    }
    ret = realpath(des_dir, abs_des_dir);
    if (NULL == ret) {
        printf("readlink %s error.%s\n", src_dir, strerror(errno));
        return;
    }

    if (abs_des_dir == strstr(abs_des_dir, abs_src_dir)) {
        printf("des dir:%s in src dir:%s. recursive error.\n", des_dir, src_dir);
        return;
    }
    
    handle_adddir_(fd, type, abs_src_dir, abs_des_dir);
    return;
}
