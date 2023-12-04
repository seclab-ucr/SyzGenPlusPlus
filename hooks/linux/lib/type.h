
#ifndef TYPE_HEADER_H
#define TYPE_HEADER_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "hook.h"

#define MAX(a, b) (a) < (b) ? (b) : (a)

typedef enum type {
    POINTER = 0,
    STRUCTURE,
    BUFFER,
} type_t;

static char *TypeName[] = {"ptr", "struct", "buffer"};

typedef int dir_t;
const dir_t DirIn = 1, DirOut = 2, DirInOut = 3;

typedef struct base {
    unsigned int offset;
    unsigned int size;
    type_t       type;
} base_t;

typedef struct node {
    base_t *data;
    struct node *next;
} node_t;

typedef struct pointer {
    base_t base;
    base_t *res;
    unsigned long addr;
    dir_t  dir;
} pointer_t;

typedef struct structure {
    base_t base;
    node_t head;
} structure_t;

typedef struct buffer {
    base_t base;
} buffer_t;

int get_num_of_fields(structure_t *ptr) {
    int ret = 0;
    node_t *cur = ptr->head.next;
    while (cur != NULL) {
        ret++;
        cur = cur->next;
    }
    return ret;
}

void append_node(structure_t *ptr, node_t *node) {
    node_t *cur = &(ptr->head);
    while (cur->next)
        cur = cur->next;
    cur->next = node;
    ptr->base.size += node->data->size;
}

void replace_node(structure_t *ptr, node_t *node) {
    node_t *cur = ptr->head.next;
    node_t *prev = &ptr->head;
    while (cur) {
        if (
            cur->data->offset == node->data->offset &&
            cur->data->size == node->data->size
        ) {
            prev->next = node;
            node->next = cur->next;
            free(cur->data);
            free(cur);
            return;
        }
        prev = cur;
        cur = cur->next;
    }
    assert(0);
}

node_t *create_node(base_t *data) {
    node_t *node = (node_t *)malloc(sizeof(node_t));
    node->data = data;
    node->next = NULL;
    return node;
}

structure_t *create_struct() {
    structure_t *res = (structure_t *)malloc(sizeof(structure_t));
    res->base.size = 0;
    res->base.offset = 0;
    res->base.type = STRUCTURE;
    res->head.data = NULL; // dummy head
    return res;
}

buffer_t *create_buffer(unsigned int offset, unsigned int size) {
    buffer_t *buffer = (buffer_t *)malloc(sizeof(buffer_t));
    buffer->base.type = BUFFER;
    buffer->base.offset = offset;
    buffer->base.size = size;
    return buffer;
}

pointer_t *create_pointer(unsigned long addr) {
    pointer_t *pointer = (pointer_t *)malloc(sizeof(pointer_t));
    pointer->addr = addr;
    pointer->base.type = POINTER;
    pointer->base.size = sizeof(unsigned long);
    pointer->base.offset = 0;
    pointer->res = NULL;
    return pointer;
}

void refine_structure(structure_t *ptr, unsigned int left, unsigned int right) {
    base_t *data;
    node_t *cur = ptr->head.next;
    node_t *prev = &(ptr->head);
    while (cur) {
        if (cur->data->offset == left && cur->data->size + cur->data->offset == right) {
            // exactly the same
            break;
        }
        if (cur->data->offset <= left && cur->data->size + cur->data->offset >= right) {
            // contain it, hence we need to split it
            assert(cur->data->type == BUFFER);
            unsigned int offset[3] = {
                cur->data->offset, left, right,
            };
            unsigned int size[3] = {
                left - cur->data->offset,
                right - left,
                cur->data->offset + cur->data->size - right,
            };
            for (int i = 0; i < 3; i++) {
                if (size[i]) {
                    node_t *new_node = create_node((base_t *)create_buffer(offset[i], size[i]));
                    prev->next = new_node;
                    prev = new_node;
                }
            }
            prev->next = cur->next;
            break;
        }
        // TODO: merge
        prev = cur;
        cur = cur->next;
    }
}

base_t *traversal(base_t *ptr) {
    pointer_t *pointer;
    structure_t *structure;
    node_t *cur;
    switch (ptr->type)
    {
    case POINTER:
        pointer = (pointer_t *)ptr;
        if (pointer->res) {
            pointer->res = traversal(pointer->res);
        }
        break;
    case STRUCTURE:
        structure = (structure_t *)ptr;
        cur = structure->head.next;
        while (cur) {
            cur->data = traversal((base_t *)cur->data);
            cur = cur->next;
        }
        if (get_num_of_fields(structure) == 1) {
            return structure->head.next->data;
        }
        break;
    case BUFFER:
    default:
        break;
    }
    return ptr;
}

void show_type(base_t *);

void show_base(base_t *base) {
    printf("\"size\": %d, \"offset\": %d, \"type\": \"%s\"", base->size, base->offset, TypeName[base->type]);
}

void show_buffer(buffer_t *buffer) {
    printf("{");
    show_base(&buffer->base);
    printf("}");
}

void show_pointer(pointer_t *ptr) {
    printf("{");
    show_base(&ptr->base);
    printf(", \"dir\": %d", ptr->dir);
    if (ptr->res) {
        printf(", \"ref\": ");
        show_type(ptr->res);
    }
    printf("}");
}

void show_structure(structure_t *ptr) {
    node_t *cur = ptr->head.next;
    int i = 0;

    printf("{");
    show_base(&ptr->base);
    printf(", \"fields\": [");
    while (cur) {
        if (i != 0)
            printf(", ");
        i++;

        show_type(cur->data);
        cur = cur->next;
    }
    printf("]");
    printf("}");
}

void show_type(base_t *ptr) {
    switch (ptr->type)
    {
    case POINTER:
        show_pointer((pointer_t *)ptr);
        break;
    case STRUCTURE:
        show_structure((structure_t *)ptr);
        break;
    case BUFFER:
        show_buffer((buffer_t *)ptr);
        break;
    default:
        show_base(ptr);
    }
}

// syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
base_t *analyze_layout(unsigned long base, hook_entry_t *entries, unsigned int n) {
    // entries is in ascending order based on their addresses
    unsigned int i;
    structure_t *res;
    buffer_t *buffer;
    node_t *node;
    unsigned long addr;
    pointer_t *pointer = create_pointer(base);
    for (i = 0; i < n; i++) {
        hook_entry_t* entry = &entries[i];
        if (entry->addr == base) {
            if (pointer->res == NULL) {
                res = create_struct();
                buffer = create_buffer(0, entry->size);
                append_node(res, create_node((base_t *)buffer));
                pointer->res = (base_t *)res;
            } else {
                // TOOD: insert new node to the structure
                refine_structure((structure_t *)pointer->res, 0, entry->size);
            }
            pointer->dir |= ((entry->id == COPY_TO_USER) ? DirOut : DirIn);
        } else if (pointer->res && entry->addr == base + pointer->res->size) {
            // append a new node
            buffer = create_buffer(pointer->res->size, entry->size);
            if (pointer->res->type == STRUCTURE) {
                append_node((structure_t *)pointer->res, create_node((base_t *)buffer));
            }
        }
    }

    // assume pointers are 8-byte aligned
    for (addr = base; addr < base + pointer->res->size; addr += sizeof(unsigned long)) {
        unsigned long value = *(unsigned long *)addr;
        for (i = 0; i < n; i++) {
            if (entries[i].addr == value) {
                // find a pointer
                pointer_t *ptr = (pointer_t *)analyze_layout(value, entries, n);
                unsigned int offset = addr - base;
                ptr->base.offset = offset;
                refine_structure((structure_t *)pointer->res, offset, offset + ptr->base.size);
                replace_node((structure_t *)pointer->res, create_node((base_t *)ptr));
                break;
            }
        }
    }

    return traversal((base_t *)pointer);
}

#endif