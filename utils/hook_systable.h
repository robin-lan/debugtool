#pragma once
#ifndef HOOK_SYS_TABLE_H
#define HOOK_SYS_TABLE_H

typedef void *ptr_t;

int hook_syscall(int call_num, ptr_t new_fn, ptr_t *old_fn);
void unhook_syscall(int call_num, ptr_t old_fn);
int hook_syscall_count(int call_num, ptr_t new_fn, ptr_t *old_fn, atomic_t *);
void unhook_syscall_count(int call_num, ptr_t old_fn, atomic_t *);
void *get_syscall(int call_num);

void dec_runhook_count(atomic_t **count);

#define CRITICAL_COUNT_INHOOK                                                  \
    atomic_t *p_runhook_count                                                  \
        __attribute__((__cleanup__(dec_runhook_count))) = &runhook_count;      \
    atomic_inc(&runhook_count);

#endif
