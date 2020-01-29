// Required definitions
#include <stdint.h>
typedef uintptr_t target_ulong;
#define h2g(x) (x)
#define g2h(x) (x)

// Include the impl
#include "asan-giovese-inl.h"

// Test-only headers
#include "pmparser.h"
#include <stdio.h>

target_ulong get_pc() {

  return (target_ulong)__builtin_return_address(0);

}

void asan_giovese_populate_context(struct call_context* ctx, target_ulong pc) {

  ctx->addresses = calloc(sizeof(void*), 16);
  int i;
  ctx->size = 1;
  ctx->tid = 0;
  ctx->addresses[0] = pc;

  for (i = 1; i < 16; ++i) {

    switch (i - 1) {
\
#define _RA_CASE(x) \
  case x: ctx->addresses[i] = (target_ulong)__builtin_return_address(x); break;
      _RA_CASE(0)
      _RA_CASE(1)
      _RA_CASE(2)
      _RA_CASE(3)
      _RA_CASE(4)
      _RA_CASE(5)
      _RA_CASE(6)
      _RA_CASE(7)
      _RA_CASE(8)
      _RA_CASE(9)
      _RA_CASE(10)
      _RA_CASE(11)
      _RA_CASE(12)
      _RA_CASE(13)
      _RA_CASE(14)

    }

    if (ctx->addresses[i] && (uintptr_t)ctx->addresses[i] < 0x7fffffffffff)
      ++ctx->size;
    else
      break;

  }

}

char* asan_giovese_printaddr(target_ulong guest_addr) {

  procmaps_iterator* maps = pmparser_parse(-1);
  procmaps_struct*   maps_tmp = NULL;

  uintptr_t a = (uintptr_t)guest_addr;

  while ((maps_tmp = pmparser_next(maps)) != NULL) {

    if (a >= (uintptr_t)maps_tmp->addr_start &&
        a < (uintptr_t)maps_tmp->addr_end) {

      size_t l = strlen(maps_tmp->pathname) + 32;
      char*  s = malloc(l);
      snprintf(s, l, " (%s+0x%lx)", maps_tmp->pathname,
               a - (uintptr_t)maps_tmp->addr_start);

      pmparser_free(maps);
      return s;

    }

  }

  pmparser_free(maps);
  return NULL;

}

char data[1000];

int main() {

  asan_giovese_init();

  asan_giovese_poison_region((target_ulong)data, 16, ASAN_HEAP_LEFT_RZ);
  asan_giovese_poison_region((target_ulong)&data[16 + 10], 16 + 6,
                             ASAN_HEAP_RIGHT_RZ);

  struct call_context* ctx = calloc(sizeof(struct call_context), 1);
  asan_giovese_populate_context(ctx, get_pc());
  asan_giovese_alloc_insert((target_ulong)&data[16],
                            (target_ulong)&data[16 + 10], ctx);

  asan_giovese_poison_region((target_ulong)&data[16], 16, ASAN_HEAP_FREED);
  struct chunk_info* ckinfo =
      asan_giovese_alloc_search((target_ulong)&data[16]);
  if (ckinfo) {

    ckinfo->free_ctx = calloc(sizeof(struct call_context), 1);
    asan_giovese_populate_context(ckinfo->free_ctx, get_pc());

  }

  target_ulong          pc = get_pc();
  register target_ulong sp asm("rsp");
  register target_ulong bp asm("rbp");

  const int IDX = 18;

  printf("<test> accessing %p\n", &data[IDX]);

  if (asan_giovese_loadN((target_ulong)&data[IDX], 11))
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, (target_ulong)&data[IDX],
                                  11, pc, bp, sp);

}

