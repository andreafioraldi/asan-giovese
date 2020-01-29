/*
  BSD 2-Clause License

  Copyright (c) 2020, Andrea Fioraldi
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice, this
     list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "asan-giovese.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>

#define DEFAULT_REDZONE_SIZE 32

// ------------------------------------------------------------------------- //
// Alloc
// ------------------------------------------------------------------------- //

#include "interval-tree/rbtree.h"
#include "interval-tree/interval_tree_generic.h"

// TODO use a mutex for locking insert/delete

struct alloc_tree_node {

  struct rb_node    rb;
  struct chunk_info ckinfo;
  TARGET_ULONG      __subtree_last;

};

#define START(node) ((node)->ckinfo.start)
#define LAST(node) ((node)->ckinfo.end)

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

  struct alloc_tree_node *prev_node = alloc_tree_iter_first(&root, start, end);
  while (prev_node) {
    
    struct alloc_tree_node *n = alloc_tree_iter_next(prev_node, start, end);
    free(prev_node->ckinfo.alloc_ctx);
    free(prev_node->ckinfo.free_ctx);
    alloc_tree_remove(prev_node, &root);
    prev_node = n;
  
  }

  struct alloc_tree_node *node = calloc(sizeof(struct alloc_tree_node), 1);
  node->ckinfo.start = start;
  node->ckinfo.end = end;
  node->ckinfo.alloc_ctx = alloc_ctx;
  alloc_tree_insert(node, &root);

}

// ------------------------------------------------------------------------- //
// Init
// ------------------------------------------------------------------------- //

void* __ag_high_shadow = HIGH_SHADOW_ADDR;
void* __ag_low_shadow = LOW_SHADOW_ADDR;

void asan_giovese_init(void) {

  assert(mmap(__ag_high_shadow, HIGH_SHADOW_SIZE, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
              0) != MAP_FAILED);
  assert(mmap(__ag_low_shadow, LOW_SHADOW_SIZE, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
              0) != MAP_FAILED);

}

// ------------------------------------------------------------------------- //
// Checks
// ------------------------------------------------------------------------- //

int asan_giovese_load1(void* addr) {

  int8_t* shadow_addr = (int8_t*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  int8_t  k = *shadow_addr;
  return k != 0 && (intptr_t)(((uintptr_t)addr & 7) + 1) > k;

}

int asan_giovese_load2(void* addr) {

  int8_t* shadow_addr = (int8_t*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  int8_t  k = *shadow_addr;
  return k != 0 && (intptr_t)(((uintptr_t)addr & 7) + 2) > k;

}

int asan_giovese_load4(void* addr) {

  int8_t* shadow_addr = (int8_t*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  int8_t  k = *shadow_addr;
  return k != 0 && (intptr_t)(((uintptr_t)addr & 7) + 4) > k;

}

int asan_giovese_load8(void* addr) {

  int8_t* shadow_addr = (int8_t*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  return (*shadow_addr);

}

int asan_giovese_store1(void* addr) {

  int8_t* shadow_addr = (int8_t*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  int8_t  k = *shadow_addr;
  return k != 0 && (intptr_t)(((uintptr_t)addr & 7) + 1) > k;

}

int asan_giovese_store2(void* addr) {

  int8_t* shadow_addr = (int8_t*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  int8_t  k = *shadow_addr;
  return k != 0 && (intptr_t)(((uintptr_t)addr & 7) + 2) > k;

}

int asan_giovese_store4(void* addr) {

  int8_t* shadow_addr = (int8_t*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  int8_t  k = *shadow_addr;
  return k != 0 && (intptr_t)(((uintptr_t)addr & 7) + 4) > k;

}

int asan_giovese_store8(void* addr) {

  int8_t* shadow_addr = (int8_t*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  return (*shadow_addr);

}

int asan_giovese_loadN(void* addr, size_t n) {

  if (!n) return 0;

  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;
  uintptr_t last_8 = end & ~7;

  if (start & 0x7) {

    uintptr_t next_8 = (start & ~7) + 8;
    size_t    first_size = next_8 - start;

    if (n <= first_size) {

      int8_t* shadow_addr = (int8_t*)(start >> 3) + SHADOW_OFFSET;
      int8_t  k = *shadow_addr;
      return k != 0 && ((intptr_t)((start & 7) + n) > k);

    }

    int8_t* shadow_addr = (int8_t*)(start >> 3) + SHADOW_OFFSET;
    int8_t  k = *shadow_addr;
    if (k != 0 && ((intptr_t)((start & 7) + first_size) > k)) return 1;

    start = next_8;

  }

  while (start < last_8) {

    int8_t* shadow_addr = (int8_t*)(start >> 3) + SHADOW_OFFSET;
    if (*shadow_addr) return 1;
    start += 8;

  }

  if (last_8 != end) {

    size_t  last_size = end - last_8;
    int8_t* shadow_addr = (int8_t*)(start >> 3) + SHADOW_OFFSET;
    int8_t  k = *shadow_addr;
    return k != 0 && ((intptr_t)((start & 7) + last_size) > k);

  }

  return 0;

}

int asan_giovese_storeN(void* addr, size_t n) {

  if (!n) return 0;

  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;
  uintptr_t last_8 = end & ~7;

  if (start & 0x7) {

    uintptr_t next_8 = (start & ~7) + 8;
    size_t    first_size = next_8 - start;

    if (n <= first_size) {

      int8_t* shadow_addr = (int8_t*)(start >> 3) + SHADOW_OFFSET;
      int8_t  k = *shadow_addr;
      return k != 0 && ((intptr_t)((start & 7) + n) > k);

    }

    int8_t* shadow_addr = (int8_t*)(start >> 3) + SHADOW_OFFSET;
    int8_t  k = *shadow_addr;
    if (k != 0 && ((intptr_t)((start & 7) + first_size) > k)) return 1;

    start = next_8;

  }

  while (start < last_8) {

    int8_t* shadow_addr = (int8_t*)(start >> 3) + SHADOW_OFFSET;
    if (*shadow_addr) return 1;
    start += 8;

  }

  if (last_8 != end) {

    size_t  last_size = end - last_8;
    int8_t* shadow_addr = (int8_t*)(start >> 3) + SHADOW_OFFSET;
    int8_t  k = *shadow_addr;
    return k != 0 && ((intptr_t)((start & 7) + last_size) > k);

  }

  return 0;

}

// ------------------------------------------------------------------------- //
// Poison
// ------------------------------------------------------------------------- //

void asan_giovese_poison_region(void const volatile* addr, size_t n,
                                uint8_t poison_byte) {

  if (!n) return;

  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;
  uintptr_t last_8 = end & ~7;

  if (start & 0x7) {

    uintptr_t next_8 = (start & ~7) + 8;
    size_t    first_size = next_8 - start;

    if (n < first_size) {

      // this lead to false positives
      // uint8_t* shadow_addr = (uint8_t*)(start >> 3) + SHADOW_OFFSET;
      // *shadow_addr = 8 - n;
      return;

    }

    uint8_t* shadow_addr = (uint8_t*)((uintptr_t)start >> 3) + SHADOW_OFFSET;
    *shadow_addr = 8 - first_size;

    start = next_8;

  }

  while (start < last_8) {

    uint8_t* shadow_addr = (uint8_t*)((uintptr_t)start >> 3) + SHADOW_OFFSET;
    *shadow_addr = poison_byte;
    start += 8;

  }

  /* if (last_8 != end) {  // TODO

    size_t last_size = end - last_8;
    uint8_t*  shadow_addr = (uint8_t*)(start >> 3) + SHADOW_OFFSET;
    *shadow_addr = last_size;

  }*/

}

void asan_giovese_user_poison_region(void const volatile* addr, size_t n) {

  asan_giovese_poison_region(addr, n, ASAN_USER);

}

void asan_giovese_unpoison_region(void const volatile* addr, size_t n) {

  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;

  while (start < end) {

    uint8_t* shadow_addr = (uint8_t*)(start >> 3) + SHADOW_OFFSET;
    *shadow_addr = 0;
    start += 8;

  }

}

// ------------------------------------------------------------------------- //
// Report
// ------------------------------------------------------------------------- //

static const char* access_type_str[] = {"READ", "WRITE"};

static const char* poisoned_strerror(uint8_t poison_byte) {

  switch (poison_byte) {

    case ASAN_HEAP_RZ:
    case ASAN_HEAP_LEFT_RZ:
    case ASAN_HEAP_RIGHT_RZ: return "heap-buffer-overflow";
    case ASAN_HEAP_FREED: return "heap-use-after-free";

  }

  return "use-after-poison";

}

static const char* poisoned_find_error(void* addr, size_t n,
                                       void** fault_addr) {

  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;
  int       have_partials = 0;

  while (start < end) {

    int8_t* shadow_addr = (int8_t*)(start >> 3) + SHADOW_OFFSET;
    switch (*shadow_addr) {

      case ASAN_VALID: break;
      case ASAN_PARTIAL1:
      case ASAN_PARTIAL2:
      case ASAN_PARTIAL3:
      case ASAN_PARTIAL4:
      case ASAN_PARTIAL5:
      case ASAN_PARTIAL6:
      case ASAN_PARTIAL7: {

        have_partials = 1;
        uintptr_t a =
            (((uintptr_t)shadow_addr - SHADOW_OFFSET) << 3) + *shadow_addr;
        if (*fault_addr == NULL && a >= start && a < end)
          *fault_addr = (void*)a;
        break;

      }

      default: {

        if (*fault_addr == NULL) *fault_addr = (void*)start;
        return poisoned_strerror(*shadow_addr);

      }

    }

    start += 8;

  }

  if (have_partials) {

    uint8_t* last_shadow_addr = (uint8_t*)((end - 1) >> 3) + SHADOW_OFFSET;
    uint8_t* out_shadow_addr = last_shadow_addr + 1;
    return poisoned_strerror(*out_shadow_addr);

  }

  if (*fault_addr == NULL) *fault_addr = addr;
  return "use-after-poison";

}

static int is_a_shadow_addr(uint8_t* shadow_addr) {

  uintptr_t a = (uintptr_t)shadow_addr;
  return (a >= (uintptr_t)__ag_high_shadow &&
          a < ((uintptr_t)__ag_high_shadow + HIGH_SHADOW_SIZE)) ||
         (a >= (uintptr_t)__ag_low_shadow &&
          a < ((uintptr_t)__ag_low_shadow + LOW_SHADOW_SIZE));

}

static void print_shadow_line(uint8_t* shadow_addr) {

  if (!is_a_shadow_addr(shadow_addr)) return;

  fprintf(stderr,
          "  0x%012" PRIxPTR
          ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
          "%02x %02x %02x\n",
          (uintptr_t)shadow_addr, shadow_addr[0], shadow_addr[1],
          shadow_addr[2], shadow_addr[3], shadow_addr[4], shadow_addr[5],
          shadow_addr[6], shadow_addr[7], shadow_addr[8], shadow_addr[9],
          shadow_addr[10], shadow_addr[11], shadow_addr[12], shadow_addr[13],
          shadow_addr[14], shadow_addr[15]);

}

static void print_shadow_line_fault(uint8_t* shadow_addr,
                                    uint8_t* shadow_fault_addr) {

  if (!is_a_shadow_addr(shadow_addr)) return;

  int         i = shadow_fault_addr - shadow_addr;
  const char* format = "=>0x%012" PRIxPTR
                       ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
                       "%02x %02x %02x %02x %02x %02x\n";
  switch (i) {

    case 0:
      format = "=>0x%012" PRIxPTR
               ":[%02x]%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 1:
      format = "=>0x%012" PRIxPTR
               ": %02x[%02x]%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 2:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x[%02x]%02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 3:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x[%02x]%02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 4:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x[%02x]%02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 5:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x[%02x]%02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 6:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x[%02x]%02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 7:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x %02x[%02x]%02x %02x %02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 8:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x %02x %02x[%02x]%02x %02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 9:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x %02x %02x %02x[%02x]%02x %02x "
               "%02x %02x %02x %02x\n";
      break;
    case 10:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x[%02x]%02x "
               "%02x %02x %02x %02x\n";
      break;
    case 11:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x[%02x]%02x %02x %02x %02x\n";
    case 12:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x[%02x]%02x %02x %02x\n";
      break;
    case 13:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x[%02x]%02x %02x\n";
      break;
    case 14:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x[%02x]%02x\n";
      break;
    case 15:
      format = "=>0x%012" PRIxPTR
               ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x[%02x]\n";
      break;

  }

  fprintf(stderr, format, (uintptr_t)shadow_addr, shadow_addr[0],
          shadow_addr[1], shadow_addr[2], shadow_addr[3], shadow_addr[4],
          shadow_addr[5], shadow_addr[6], shadow_addr[7], shadow_addr[8],
          shadow_addr[9], shadow_addr[10], shadow_addr[11], shadow_addr[12],
          shadow_addr[13], shadow_addr[14], shadow_addr[15]);

}

static void print_shadow(uint8_t* shadow_addr) {

  uintptr_t center = (uintptr_t)shadow_addr & ~15;
  print_shadow_line((void*)(center - 16 * 5));
  print_shadow_line((void*)(center - 16 * 4));
  print_shadow_line((void*)(center - 16 * 3));
  print_shadow_line((void*)(center - 16 * 2));
  print_shadow_line((void*)(center - 16));
  print_shadow_line_fault((void*)(center), shadow_addr);
  print_shadow_line((void*)(center + 16));
  print_shadow_line((void*)(center + 16 * 2));
  print_shadow_line((void*)(center + 16 * 3));
  print_shadow_line((void*)(center + 16 * 4));
  print_shadow_line((void*)(center + 16 * 5));

}

static void print_alloc_location_chunk(struct chunk_info* ckinfo,
                                       TARGET_ULONG       fault_addr) {

  if (fault_addr >= ckinfo->start && fault_addr < ckinfo->end)
    fprintf(stderr,
            "0x%012" PRIxPTR
            " is located %ld bytes inside of %ld-byte region [0x%012" PRIxPTR
            ",0x%012" PRIxPTR ")\n",
            fault_addr, fault_addr - ckinfo->start, ckinfo->end - ckinfo->start,
            ckinfo->start, ckinfo->end);
  else if (ckinfo->start >= fault_addr)
    fprintf(
        stderr,
        "0x%012" PRIxPTR
        " is located %ld bytes to the left of %ld-byte region [0x%012" PRIxPTR
        ",0x%012" PRIxPTR ")\n",
        fault_addr, ckinfo->start - fault_addr, ckinfo->end - ckinfo->start,
        ckinfo->start, ckinfo->end);
  else
    fprintf(
        stderr,
        "0x%012" PRIxPTR
        " is located %ld bytes to the right of %ld-byte region [0x%012" PRIxPTR
        ",0x%012" PRIxPTR ")\n",
        fault_addr, fault_addr - ckinfo->end, ckinfo->end - ckinfo->start,
        ckinfo->start, ckinfo->end);

  if (ckinfo->free_ctx) {

    fprintf(stderr, "freed by thread T%d here:\n", ckinfo->free_ctx->tid);
    size_t i;
    for (i = 0; i < ckinfo->free_ctx->size; ++i) {

      char* printable = asan_giovese_printaddr(ckinfo->free_ctx->addresses[i]);
      if (printable)
        fprintf(stderr, "    #%lu 0x%012" PRIxPTR "%s\n", i,
                ckinfo->free_ctx->addresses[i], printable);
      else
        fprintf(stderr, "    #%lu 0x%012" PRIxPTR "\n", i,
                ckinfo->free_ctx->addresses[i]);

    }

    fputc('\n', stderr);

    fprintf(stderr, "previously allocated by thread T%d here:\n",
            ckinfo->free_ctx->tid);

  } else

    fprintf(stderr, "allocated by thread T%d here:\n", ckinfo->alloc_ctx->tid);

  size_t i;
  for (i = 0; i < ckinfo->alloc_ctx->size; ++i) {

    char* printable = asan_giovese_printaddr(ckinfo->alloc_ctx->addresses[i]);
    if (printable)
      fprintf(stderr, "    #%lu 0x%012" PRIxPTR "%s\n", i,
              ckinfo->alloc_ctx->addresses[i], printable);
    else
      fprintf(stderr, "    #%lu 0x%012" PRIxPTR "\n", i,
              ckinfo->alloc_ctx->addresses[i]);

  }

  fputc('\n', stderr);

}

static void print_alloc_location(TARGET_ULONG addr, TARGET_ULONG fault_addr) {

  struct chunk_info* ckinfo = asan_giovese_alloc_search(fault_addr);
  if (!ckinfo && addr != fault_addr) ckinfo = asan_giovese_alloc_search(addr);

  if (ckinfo) {

    print_alloc_location_chunk(ckinfo, fault_addr);
    return;

  }

  int i = 0;
  while (!ckinfo && i < DEFAULT_REDZONE_SIZE)
    ckinfo = asan_giovese_alloc_search(fault_addr - (i++));
  if (ckinfo) {

    print_alloc_location_chunk(ckinfo, fault_addr);
    return;

  }

  i = 0;
  while (!ckinfo && i < DEFAULT_REDZONE_SIZE)
    ckinfo = asan_giovese_alloc_search(fault_addr + (i++));
  if (ckinfo) {

    print_alloc_location_chunk(ckinfo, fault_addr);
    return;

  }

  fprintf(stderr, "Address 0x%012" PRIxPTR " is a wild pointer.\n", fault_addr);

}

void asan_giovese_report_and_crash(int access_type, void* addr, size_t n,
                                   TARGET_ULONG guest_addr, TARGET_ULONG pc,
                                   TARGET_ULONG bp, TARGET_ULONG sp) {

  struct call_context ctx;
  asan_giovese_populate_context(&ctx, pc);
  void*       fault_addr = NULL;
  const char* error_type = poisoned_find_error(addr, n, &fault_addr);

  fprintf(stderr,
          "=================================================================\n"
          "==%d==ERROR: AddressSanitizer: %s on address 0x%012" PRIxPTR
          " at pc 0x%012" PRIxPTR " bp 0x%012" PRIxPTR " sp 0x%012" PRIxPTR
          "\n",
          getpid(), error_type, guest_addr, pc, bp, sp);

  fprintf(stderr, "%s of size %lu at 0x%012" PRIxPTR " thread T%d\n",
          access_type_str[access_type], n, guest_addr, ctx.tid);
  size_t i;
  for (i = 0; i < ctx.size; ++i) {

    char* printable = asan_giovese_printaddr(ctx.addresses[i]);
    if (printable)
      fprintf(stderr, "    #%lu 0x%012" PRIxPTR "%s\n", i, ctx.addresses[i],
              printable);
    else
      fprintf(stderr, "    #%lu 0x%012" PRIxPTR "\n", i, ctx.addresses[i]);

  }

  fputc('\n', stderr);

  TARGET_ULONG guest_fault_addr = guest_addr + (fault_addr - addr);
  print_alloc_location(guest_addr, guest_fault_addr);

  char* printable_pc = asan_giovese_printaddr(pc);
  if (!printable_pc) printable_pc = "";
  fprintf(stderr,
          "SUMMARY: AddressSanitizer: %s%s\n"
          "Shadow bytes around the buggy address:\n",
          error_type, printable_pc);

  uint8_t* shadow_fault_addr =
      (uint8_t*)(((uintptr_t)fault_addr >> 3) + SHADOW_OFFSET);
  print_shadow(shadow_fault_addr);

  fprintf(
      stderr,
      "Shadow byte legend (one shadow byte represents 8 application bytes):\n"
      "  Addressable:           00\n"
      "  Partially addressable: 01 02 03 04 05 06 07\n"
      "  Heap left redzone:       fa\n"
      "  Freed heap region:       fd\n"
      "  Stack left redzone:      f1\n"
      "  Stack mid redzone:       f2\n"
      "  Stack right redzone:     f3\n"
      "  Stack after return:      f5\n"
      "  Stack use after scope:   f8\n"
      "  Global redzone:          f9\n"
      "  Global init order:       f6\n"
      "  Poisoned by user:        f7\n"
      "  Container overflow:      fc\n"
      "  Array cookie:            ac\n"
      "  Intra object redzone:    bb\n"
      "  ASan internal:           fe\n"
      "  Left alloca redzone:     ca\n"
      "  Right alloca redzone:    cb\n"
      "  Shadow gap:              cc\n"
      "==%d==ABORTING\n",
      getpid());

  abort();

}

