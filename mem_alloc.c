/*
 * Dynamic General Purpose Memory Allocator
 * Allows user to call mem_alloc(void *) and mem_free(void *)
 * Author: John (Jack) Edwards - edwarddn@bc.edu
 */

#include "mem_alloc.h"

Header * free_list;

int is_allocated(Header * header) { 
    return (header->size & 1);
}

void set_allocated(Header * header) {
    header->size |= 1;
}

void set_free(Header * header) {
    header->size &= ~1;
}

Header * get_header(void * mem) {
    return (Header *)((char *)mem - sizeof(Header));
}

int same_page(Header * h1, Header * h2) {
    return ((intptr_t)h1 & ~0xfff) == ((intptr_t)h2 & ~0xfff);
}

int mem_init() {
    void * ptr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (ptr == MAP_FAILED) {
        return FAILURE;
    }
    Header * header = (Header *) ptr;
    header->size = PAGE_SIZE - sizeof(Header);
    header->previous = NULL;
    header->next = NULL;

    free_list = header;
    return SUCCESS;
}

int mem_extend(Header * last) {
    void * ptr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (ptr == MAP_FAILED) {
        return FAILURE;
    }
    Header * new_header = (Header *)ptr;
    new_header->size = PAGE_SIZE - sizeof(Header);
    new_header->next = last->next;
    new_header->previous = last;
    last->next = new_header;

    return SUCCESS;
}

void * mem_alloc(size_t requested_size) {
    int complement = requested_size % WORD_SIZE;
    size_t aligned_size = requested_size + (WORD_SIZE - complement);
    if (complement == 0) {
        aligned_size -= WORD_SIZE;
    }

    if (aligned_size > PAGE_SIZE - sizeof(Header)) {
        return NULL;
    }

    if (free_list == NULL) {
        int ret = mem_init(); 
        if (ret == FAILURE) {
            return NULL;
        }
    }

    Header * header = free_list;
    while (header->next && (is_allocated(header) || header->size < aligned_size)) {
        header = header->next;
    }
   
    if (header->next == NULL) {
        if (header->size < aligned_size || is_allocated(header)) {
                int ret_2 = mem_extend(header);
                if (ret_2 == FAILURE) {
                    return NULL;
                } else {
                    header = header->next;
                }
        }
    }

    void * payload_address = (void *)((char *)header + sizeof(Header)); 
    if (header->size > aligned_size + sizeof(Header)) {
        Header * new_header = (Header *) ((char *)header + sizeof(Header) + aligned_size);
        new_header->size = header->size - aligned_size - sizeof(Header);
        header->size = aligned_size;
        new_header->previous = header;
        new_header->next = header->next;
        header->next = new_header;
        if (new_header->next) {
            new_header->next->previous = new_header;
        }
    }
    set_allocated(header);

    return payload_address;
}

void mem_free(void * ptr) {
    Header * header = get_header(ptr);
    set_free(header);

    if (header->next && !is_allocated(header->next) && same_page(header, header->next)) {
        header->size += header->next->size + sizeof(Header);
        header->next = header->next->next;
        if (header->next) {
            header->next->previous = header;
        }
    }

    if (header->previous && !is_allocated(header->previous) && same_page(header, header->previous)) {
        header = header->previous;
        header->size += header->next->size + sizeof(Header);
        header->next = header->next->next;
        if (header->next) {
            header->next->previous = header;
        }
    }

    if (header->size == PAGE_SIZE - sizeof(Header)) {
        if (header->previous) {
            header->previous->next = header->next;
            if (header->next) {
                header->next->previous = header->previous;
            }
        } else if (header->next) {
            free_list = header->next;
            header->next->previous = NULL;
        } else {
            free_list = NULL;
        }

        munmap((void *)header, PAGE_SIZE);
    }
}

void print_list() {
    Header * current = free_list;
    if (current == NULL) {
        printf("(Empty List.)\n");
        return;
    } else {
        printf("%p -> ", current);
        while (current->next) {
            current = current->next;
            printf("%p -> ", current);
        }
        printf("\n");
    }
}

size_t get_size(Header * header) {
    return (header->size & ~1);
}

void print_header(Header * header) {
    printf("\tAddr: %p\n", header);
    printf("\tSize: %zu\n", get_size(header));
    printf("\tPrevious: %p\n", header->previous);
    printf("\tNext: %p\n", header->next); 
}

