#include <stdlib.h>
#include <errno.h>
#include "pairing_heap.h"
#include "log.h"
#include "main.h"
/*
typedef struct heap_node {
    struct heap_node *parent;
    struct heap_node *next_sibling;
    struct heap_node *previous_sibling;
    struct heap_node *first_child;
    struct heap_node *last_child;
	int value;
    int n_subtrees;
	struct connection_t c;
} heap_node;

typedef struct heap {
    heap_node * root;
} heap;
*/
/***********************************************
 *
 * PRIVATE FUNCTIONS 
 *
 ***********************************************/
int g_heap_num_ele;

/* link two node trees */
heap_node* heap_node_meld(heap_node *small, heap_node *big) {   
    heap_node *tmp;
    
    if (!small) return big;

    if (small->value.timeout > big->value.timeout) {
        tmp=small; small=big; big=tmp;
    }

    big->parent = small; /* small becomes the partent of big */
    if (small->first_child) { /* if small has children */
        big->next_sibling = small->first_child; /* big has a new sibling */
        big->next_sibling->previous_sibling = big; /* big is the new sibling of someone*/
    } else { /* big is to be only child */
        small->last_child = big; /* big is the last child of small */
    }
    small->first_child = big; /* big is the first child of small */

    return small;
}

/* isolate node from parent and siblings */
void heap_node_isolate(heap_node *node) {
    heap_node *prev_tmp,*next_tmp;

    prev_tmp = node->previous_sibling;
    next_tmp = node->next_sibling;

    /* remove */
    node->previous_sibling = NULL;
    if (prev_tmp) prev_tmp->next_sibling=next_tmp;
    else if (node->parent) node->parent->first_child=next_tmp;

    node->next_sibling=NULL;
    if (next_tmp) next_tmp->previous_sibling=prev_tmp;
    else if (node->parent) node->parent->last_child=prev_tmp;

    node->parent=NULL;
}

/* create a new node */
heap_node* heap_node_new(time_t value) {
    heap_node *h;

    if ((h = (heap_node*)malloc(sizeof(heap_node))) == NULL) {
		logerr("malloc error: %s", strerror(errno));
		exit(1);
	}
    /* if you want speed, use memset instead */
    h->parent = NULL;
    h->previous_sibling = NULL;
    h->next_sibling = NULL;
    h->first_child = NULL;
    h->last_child = NULL;
    h->value.timeout = value;
    return h;
}

/* free node tree */
void heap_node_free(heap_node *h) {
    heap_node * fc;

    if (!h)
        return;
    fc = h->first_child;
    free(h);
    heap_node_free(h->next_sibling);
    return heap_node_free(fc);
}

/***********************************************
 *
 * PUBLIC FUNCTIONS 
 *
 ***********************************************/

/* free heap */
void heap_free(heap *hp) {g_heap_num_ele = 0;
    heap_node_free(hp->root);
    free(hp);
}

/* get min value */
struct connection_t* heap_min(heap *h){
	if (h->root == NULL) return NULL;
	return &h->root->value;
}

/* decrease the value of the node */
void heap_decrease_key(heap *h, heap_node *node, time_t new_value) {
    node->value.timeout = new_value;
    /* if the node is not at the root of the tree, remove it and
       merge it with the root */
    if (node!=h->root) {
        /* remove the node tree from the siblings and parents*/
        heap_node_isolate(node);
        /* merge with root*/
        h->root = heap_node_meld(h->root,node);
    }
}

/* insert element to the heap */
heap_node* heap_insert(heap *h, time_t value) { g_heap_num_ele++;
    heap_node *node = heap_node_new(value);
    h->root = heap_node_meld(h->root,node);
    return node;
}

/* delete min value. classic two-pass */
void heap_delete_min(heap *hp) { g_heap_num_ele--;
    heap_node *a,*b,*next_tmp,*new_root=NULL;

    heap_node * h = hp->root;

    /* heap_node_meld in pairs, 1st and 2nd, 3rd and 4th, ...*/
    a = h->first_child;
    while(a!=NULL)
    {
        next_tmp=NULL;
        b = a->next_sibling;
        heap_node_isolate(a);
        if (b) {
            next_tmp=b->next_sibling;
            heap_node_isolate(b);
            a = heap_node_meld(a,b);
        }
        h = heap_node_meld(h,a);
        a = next_tmp;
    }

    /* attach all to the oldest one */
    a = h->first_child;
    while(a!=NULL)
    {
        b = a->next_sibling;
        if (!b) break;
        heap_node_isolate(a);
        heap_node_isolate(b);
        a = heap_node_meld(a,b);
        h = heap_node_meld(h,a);
    }

    if (h->first_child) {
        new_root = h->first_child;
        h->first_child->parent=NULL;
    }

    free(h);
    hp->root = new_root;
}

/* create a new heap */
heap * heap_new(void) {g_heap_num_ele=0;
    heap *h;
    h = (heap*)malloc(sizeof(heap));
    h->root = NULL;
    return h;
}
