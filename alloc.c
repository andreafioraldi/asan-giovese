#include "asan-giovese.h"
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "rbtree.h"
#include "interval_tree_generic.h"

// TODO use a mutex for locking insert/delete

struct alloc_tree_node {

  struct rb_node    rb;
  struct chunk_info ckinfo;
  TARGET_ULONG      __subtree_last;

};

#define START(node) ((node)->ckinfo.start)
#define LAST(node) ((node)->ckinfo.end)

static void alloc_tree_insert(struct alloc_tree_node *node, struct rb_root *root);
static void alloc_tree_remove(struct alloc_tree_node *node, struct rb_root *root);
static struct alloc_tree_node *alloc_tree_iter_first(struct rb_root *root, TARGET_ULONG start, TARGET_ULONG last);
static struct alloc_tree_node *alloc_tree_iter_next(struct alloc_tree_node *node, TARGET_ULONG start, TARGET_ULONG last);

INTERVAL_TREE_DEFINE(struct alloc_tree_node, rb, TARGET_ULONG, __subtree_last,
                     START, LAST, static, alloc_tree)

static struct rb_root root = RB_ROOT;

struct chunk_info *asan_giovese_alloc_search(TARGET_ULONG query) {

  struct alloc_tree_node *node = alloc_tree_iter_first(&root, query, query);
  if (node) return &node->ckinfo;
  return NULL;

}

void asan_giovese_alloc_insert(TARGET_ULONG start, TARGET_ULONG end,
                               struct call_context *alloc_ctx) {

  struct alloc_tree_node *node = calloc(sizeof(struct alloc_tree_node), 1);
  node->ckinfo.start = start;
  node->ckinfo.end = end;
  node->ckinfo.alloc_ctx = alloc_ctx;
  alloc_tree_insert(node, &root);

}

