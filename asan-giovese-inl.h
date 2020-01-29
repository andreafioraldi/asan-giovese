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
  target_ulong      __subtree_last;

};

#define START(node) ((node)->ckinfo.start)
#define LAST(node) ((node)->ckinfo.end)

INTERVAL_TREE_DEFINE(struct alloc_tree_node, rb, target_ulong, __subtree_last,
                     START, LAST, static, alloc_tree)

static struct rb_root root = RB_ROOT;

struct chunk_info* asan_giovese_alloc_search(target_ulong query) {

  struct alloc_tree_node* node = alloc_tree_iter_first(&root, query, query);
  if (node) return &node->ckinfo;
  return NULL;

}

void asan_giovese_alloc_insert(target_ulong start, target_ulong end,
                               struct call_context* alloc_ctx) {

  struct alloc_tree_node* prev_node = alloc_tree_iter_first(&root, start, end);
  while (prev_node) {

    struct alloc_tree_node* n = alloc_tree_iter_next(prev_node, start, end);
    free(prev_node->ckinfo.alloc_ctx);
    free(prev_node->ckinfo.free_ctx);
    alloc_tree_remove(prev_node, &root);
    prev_node = n;

  }

  struct alloc_tree_node* node = calloc(sizeof(struct alloc_tree_node), 1);
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

int asan_giovese_load1(target_ulong addr) {

  uintptr_t h = (uintptr_t)g2h(addr);
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  int8_t    k = *shadow_addr;
  return k != 0 && (intptr_t)((h & 7) + 1) > k;

}

int asan_giovese_load2(target_ulong addr) {

  uintptr_t h = (uintptr_t)g2h(addr);
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  int8_t    k = *shadow_addr;
  return k != 0 && (intptr_t)((h & 7) + 2) > k;

}

int asan_giovese_load4(target_ulong addr) {

  uintptr_t h = (uintptr_t)g2h(addr);
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  int8_t    k = *shadow_addr;
  return k != 0 && (intptr_t)((h & 7) + 4) > k;

}

int asan_giovese_load8(target_ulong addr) {

  uintptr_t h = (uintptr_t)g2h(addr);
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  return (*shadow_addr);

}

int asan_giovese_store1(target_ulong addr) {

  uintptr_t h = (uintptr_t)g2h(addr);
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  int8_t    k = *shadow_addr;
  return k != 0 && (intptr_t)((h & 7) + 1) > k;

}

int asan_giovese_store2(target_ulong addr) {

  uintptr_t h = (uintptr_t)g2h(addr);
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  int8_t    k = *shadow_addr;
  return k != 0 && (intptr_t)((h & 7) + 2) > k;

}

int asan_giovese_store4(target_ulong addr) {

  uintptr_t h = (uintptr_t)g2h(addr);
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  int8_t    k = *shadow_addr;
  return k != 0 && (intptr_t)((h & 7) + 4) > k;

}

int asan_giovese_store8(target_ulong addr) {

  uintptr_t h = (uintptr_t)g2h(addr);
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  return (*shadow_addr);

}

int asan_giovese_loadN(target_ulong addr, size_t n) {

  if (!n) return 0;

  target_ulong start = addr;
  target_ulong end = start + n;
  target_ulong last_8 = end & ~7;

  if (start & 0x7) {

    target_ulong next_8 = (start & ~7) + 8;
    size_t       first_size = next_8 - start;

    if (n <= first_size) {

      uintptr_t h = (uintptr_t)g2h(start);
      int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
      int8_t    k = *shadow_addr;
      return k != 0 && ((intptr_t)((h & 7) + n) > k);

    }

    uintptr_t h = (uintptr_t)g2h(start);
    int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
    int8_t    k = *shadow_addr;
    if (k != 0 && ((intptr_t)((h & 7) + first_size) > k)) return 1;

    start = next_8;

  }

  while (start < last_8) {

    uintptr_t h = (uintptr_t)g2h(start);
    int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
    if (*shadow_addr) return 1;
    start += 8;

  }

  if (last_8 != end) {

    uintptr_t h = (uintptr_t)g2h(start);
    size_t    last_size = end - last_8;
    int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
    int8_t    k = *shadow_addr;
    return k != 0 && ((intptr_t)((h & 7) + last_size) > k);

  }

  return 0;

}

int asan_giovese_storeN(target_ulong addr, size_t n) {

  if (!n) return 0;

  target_ulong start = addr;
  target_ulong end = start + n;
  target_ulong last_8 = end & ~7;

  if (start & 0x7) {

    target_ulong next_8 = (start & ~7) + 8;
    size_t       first_size = next_8 - start;

    if (n <= first_size) {

      uintptr_t h = (uintptr_t)g2h(start);
      int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
      int8_t    k = *shadow_addr;
      return k != 0 && ((intptr_t)((h & 7) + n) > k);

    }

    uintptr_t h = (uintptr_t)g2h(start);
    int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
    int8_t    k = *shadow_addr;
    if (k != 0 && ((intptr_t)((h & 7) + first_size) > k)) return 1;

    start = next_8;

  }

  while (start < last_8) {

    uintptr_t h = (uintptr_t)g2h(start);
    int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
    if (*shadow_addr) return 1;
    start += 8;

  }

  if (last_8 != end) {

    uintptr_t h = (uintptr_t)g2h(start);
    size_t    last_size = end - last_8;
    int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
    int8_t    k = *shadow_addr;
    return k != 0 && ((intptr_t)((h & 7) + last_size) > k);

  }

  return 0;

}

// ------------------------------------------------------------------------- //
// Poison
// ------------------------------------------------------------------------- //

void asan_giovese_poison_region(target_ulong addr, size_t n,
                                uint8_t poison_byte) {

  if (!n) return;

  target_ulong start = addr;
  target_ulong end = start + n;
  target_ulong last_8 = end & ~7;

  if (start & 0x7) {

    target_ulong next_8 = (start & ~7) + 8;
    size_t       first_size = next_8 - start;

    if (n < first_size) return;

    uintptr_t h = (uintptr_t)g2h(start);
    uint8_t*  shadow_addr = (uint8_t*)(h >> 3) + SHADOW_OFFSET;
    *shadow_addr = 8 - first_size;

    start = next_8;

  }

  while (start < last_8) {

    uintptr_t h = (uintptr_t)g2h(start);
    uint8_t*  shadow_addr = (uint8_t*)(h >> 3) + SHADOW_OFFSET;
    *shadow_addr = poison_byte;
    start += 8;

  }

}

void asan_giovese_user_poison_region(target_ulong addr, size_t n) {

  asan_giovese_poison_region(addr, n, ASAN_USER);

}

void asan_giovese_unpoison_region(target_ulong addr, size_t n) {

  target_ulong start = addr;
  target_ulong end = start + n;

  while (start < end) {

    uintptr_t h = (uintptr_t)g2h(start);
    uint8_t*  shadow_addr = (uint8_t*)(h >> 3) + SHADOW_OFFSET;
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

static const char* poisoned_find_error(target_ulong addr, size_t n,
                                       target_ulong* fault_addr) {

  target_ulong start = addr;
  target_ulong end = start + n;
  int          have_partials = 0;

  while (start < end) {

    uintptr_t rs = g2h(start);
    int8_t*      shadow_addr = (int8_t*)(rs >> 3) + SHADOW_OFFSET;
    switch (*shadow_addr) {

      case ASAN_VALID: have_partials = 0; break;
      case ASAN_PARTIAL1:
      case ASAN_PARTIAL2:
      case ASAN_PARTIAL3:
      case ASAN_PARTIAL4:
      case ASAN_PARTIAL5:
      case ASAN_PARTIAL6:
      case ASAN_PARTIAL7: {

        have_partials = 1;
        target_ulong a = (start & ~7) + *shadow_addr;
        if (*fault_addr == 0 && a >= start && a < end) *fault_addr = a;
        break;

      }

      default: {

        if (*fault_addr == 0) *fault_addr = start;
        return poisoned_strerror(*shadow_addr);

      }

    }

    start += 8;

  }

  if (have_partials) {

    uintptr_t rs = g2h((end & ~7) + 8);
    uint8_t*     last_shadow_addr = (uint8_t*)(rs >> 3) + SHADOW_OFFSET;
    return poisoned_strerror(*last_shadow_addr);

  }

  if (*fault_addr == 0) *fault_addr = addr;
  return "use-after-poison";

}

#define _MEM2SHADOW(x) ((uint8_t*)((uintptr_t)g2h(x) >> 3) + SHADOW_OFFSET)

static void print_shadow_line(target_ulong addr) {

  fprintf(
      stderr,
      "  0x%012" PRIxPTR
      ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
      "%02x %02x %02x\n",
      (uintptr_t)_MEM2SHADOW(addr), *_MEM2SHADOW(addr), *_MEM2SHADOW(addr + 8),
      *_MEM2SHADOW(addr + 16), *_MEM2SHADOW(addr + 24), *_MEM2SHADOW(addr + 32),
      *_MEM2SHADOW(addr + 40), *_MEM2SHADOW(addr + 48), *_MEM2SHADOW(addr + 56),
      *_MEM2SHADOW(addr + 64), *_MEM2SHADOW(addr + 72), *_MEM2SHADOW(addr + 80),
      *_MEM2SHADOW(addr + 88), *_MEM2SHADOW(addr + 96),
      *_MEM2SHADOW(addr + 104), *_MEM2SHADOW(addr + 112),
      *_MEM2SHADOW(addr + 120));

}

static void print_shadow_line_fault(target_ulong addr,
                                    target_ulong fault_addr) {

  int         i = (fault_addr - addr) / 8;
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

  fprintf(
      stderr, format, (uintptr_t)_MEM2SHADOW(addr), *_MEM2SHADOW(addr),
      *_MEM2SHADOW(addr + 8), *_MEM2SHADOW(addr + 16), *_MEM2SHADOW(addr + 24),
      *_MEM2SHADOW(addr + 32), *_MEM2SHADOW(addr + 40), *_MEM2SHADOW(addr + 48),
      *_MEM2SHADOW(addr + 56), *_MEM2SHADOW(addr + 64), *_MEM2SHADOW(addr + 72),
      *_MEM2SHADOW(addr + 80), *_MEM2SHADOW(addr + 88), *_MEM2SHADOW(addr + 96),
      *_MEM2SHADOW(addr + 104), *_MEM2SHADOW(addr + 112),
      *_MEM2SHADOW(addr + 120));

}

#undef _MEM2SHADOW

static void print_shadow(target_ulong addr) {

  target_ulong center = addr & ~0x80;
  print_shadow_line(center - 16 * 8 * 5);
  print_shadow_line(center - 16 * 8 * 4);
  print_shadow_line(center - 16 * 8 * 3);
  print_shadow_line(center - 16 * 8 * 2);
  print_shadow_line(center - 16 * 8);
  print_shadow_line_fault(center, addr);
  print_shadow_line(center + 16 * 8);
  print_shadow_line(center + 16 * 8 * 2);
  print_shadow_line(center + 16 * 8 * 3);
  print_shadow_line(center + 16 * 8 * 4);
  print_shadow_line(center + 16 * 8 * 5);

}

static void print_alloc_location_chunk(struct chunk_info* ckinfo,
                                       target_ulong       fault_addr) {

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

static void print_alloc_location(target_ulong addr, target_ulong fault_addr) {

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

void asan_giovese_report_and_crash(int access_type, target_ulong addr, size_t n,
                                   target_ulong pc, target_ulong bp,
                                   target_ulong sp) {

  struct call_context ctx;
  asan_giovese_populate_context(&ctx, pc);
  target_ulong fault_addr = 0;
  const char*  error_type;

  error_type = poisoned_find_error(addr, n, &fault_addr);

  fprintf(stderr,
          "=================================================================\n"
          "==%d==ERROR: AddressSanitizer: %s on address 0x%012" PRIxPTR
          " at pc 0x%012" PRIxPTR " bp 0x%012" PRIxPTR " sp 0x%012" PRIxPTR
          "\n",
          getpid(), error_type, addr, pc, bp, sp);

  fprintf(stderr, "%s of size %lu at 0x%012" PRIxPTR " thread T%d\n",
          access_type_str[access_type], n, addr, ctx.tid);
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

  print_alloc_location(addr, fault_addr);

  char* printable_pc = asan_giovese_printaddr(pc);
  if (!printable_pc) printable_pc = "";
  fprintf(stderr,
          "SUMMARY: AddressSanitizer: %s%s\n"
          "Shadow bytes around the buggy address:\n",
          error_type, printable_pc);

  print_shadow(fault_addr);

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

