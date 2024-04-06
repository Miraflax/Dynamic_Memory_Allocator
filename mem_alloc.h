#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define WORD_SIZE 8
#define SUCCESS 0
#define FAILURE -1

typedef struct Header {
    size_t size;
    struct Header * previous;
    struct Header * next;
} Header;

void * mem_alloc(size_t);
void mem_free(void *);
