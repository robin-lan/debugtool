
#ifndef DEBUG_TOOL_USER_MEM_PRINT_H
#define DEBUG_TOOL_USER_MEM_PRINT_H

char *mem_print_addr(char *output, int max_size, const char *addr, int *less_size);
char *sstrcopy(char *output, int max_size, char *src, int *less_size);
void mem_print(char *output, int max_size, const char *addr, int size, int type, int content_len);


#endif
