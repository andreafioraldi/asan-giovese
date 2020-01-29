#include "asan-giovese.h"
#include "pmparser.h"
#include <stdio.h>

TARGET_ULONG get_pc() {

  return (TARGET_ULONG)__builtin_return_address(0);

}

void asan_giovese_populate_context(struct call_context* ctx, TARGET_ULONG pc) {

  ctx->addresses = calloc(sizeof(void*), 16);
  int i;
  ctx->size = 0;
  ctx->tid = 0;
  for (i = 0; i < 16; ++i) {

    switch (i) {
\
#define _RA_CASE(x) \
  case x: ctx->addresses[i] = (TARGET_ULONG)__builtin_return_address(x); break;
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
      _RA_CASE(15)

    }

    if (ctx->addresses[i] && (uintptr_t)ctx->addresses[i] < 0x7fffffffffff)
      ++ctx->size;
    else
      break;

  }

}

char* asan_giovese_printaddr(TARGET_ULONG guest_addr) {

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

  asan_giovese_poison_region(data, 16, ASAN_HEAP_LEFT_RZ);
  asan_giovese_poison_region(&data[16 + 10], 16 + 6, ASAN_HEAP_RIGHT_RZ);

  struct call_context* ctx = calloc(sizeof(struct call_context), 1);
  asan_giovese_populate_context(ctx, 0);
  asan_giovese_alloc_insert((TARGET_ULONG)&data[16],
                            (TARGET_ULONG)&data[16 + 10], ctx);

  asan_giovese_poison_region(&data[16], 16, ASAN_HEAP_FREED);
  struct chunk_info* ckinfo =
      asan_giovese_alloc_search((TARGET_ULONG)&data[16]);
  if (ckinfo) {

    ckinfo->free_ctx = calloc(sizeof(struct call_context), 1);
    asan_giovese_populate_context(ckinfo->free_ctx, 0);

  }

  TARGET_ULONG          pc = get_pc();
  register TARGET_ULONG sp asm("rsp");
  register TARGET_ULONG bp asm("rbp");

  const int IDX = 18;

  printf("<test> accessing %p\n", &data[IDX]);

  if (asan_giovese_loadN(&data[IDX], 11))
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, &data[IDX], 11,
                                  (TARGET_ULONG)&data[IDX], pc, bp, sp);

}

