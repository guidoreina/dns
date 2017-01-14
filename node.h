#ifndef NODE_H
#define NODE_H

#include <stdlib.h>

typedef struct node_t {
  struct node_t* prev;
  struct node_t* next;
} node_t;

static inline void node_unlink(node_t* node)
{
  node->prev->next = node->next;
  node->next->prev = node->prev;
}

static inline void node_free_list(node_t* first, node_t* last)
{
  node_t* next;

  while (first != last) {
    next = first->next;
    free(first);
    first = next;
  }
}

#endif /* NODE_H */
