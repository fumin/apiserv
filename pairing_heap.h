#ifndef _PAIRING_HEAP_H_
#define _PAIRING_HEAP_H_

#include "connection.h"

extern int g_heap_num_ele;

struct heap_node {
    struct heap_node *parent;
    struct heap_node *next_sibling;
    struct heap_node *previous_sibling;
    struct heap_node *first_child;
    struct heap_node *last_child;
    //int value;
    int n_subtrees;
    struct connection_t value;
};

struct heap {
    heap_node * root;
};

void heap_free(heap *hp);
struct connection_t* heap_min(heap *h);
void heap_decrease_key(heap *h, heap_node *node, time_t delta);
heap_node* heap_insert(heap *h, time_t value);
void heap_delete_min(heap *hp);
heap * heap_new(void);

#endif
