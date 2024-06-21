
#pragma once
#ifndef DEBUG_TOOL_LOG_H
#define DEBUG_TOOL_LOG_H

int loger(const char *fmt, ...);
void write_log_file(const char *file);

void init_loger();
void release_loger();

#endif
