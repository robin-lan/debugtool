
#pragma once
#ifndef USER_FILE_H
#define USER_FILE_H

void write_file(const char *file, const char *buff, int size, int flag, int mode);
int read_file(const char *file, char *buff, int size);

#endif
