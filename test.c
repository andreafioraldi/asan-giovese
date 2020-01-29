#include "asan-giovese.h"
#include "pmparser.h"
#include <stdio.h>

void* get_pc() {

  return __builtin_return_address(0);

}

int asan_giovese_populate_context(struct call_context* ctx) {

  ctx->addresses = calloc(sizeof(void*), 16);
  int i;
  ctx->size = 0;
  ctx->tid = 0;
  for (i = 0; i < 16; ++i) {

    switch (i) {

      case 0: ctx->addresses[i] = __builtin_return_address(1); break;
      case 1: ctx->addresses[i] = __builtin_return_address(2); break;
      case 2: ctx->addresses[i] = __builtin_return_address(3); break;
      case 3: ctx->addresses[i] = __builtin_return_address(4); break;
      case 4: ctx->addresses[i] = __builtin_return_address(5); break;
      case 5: ctx->addresses[i] = __builtin_return_address(6); break;
      case 6: ctx->addresses[i] = __builtin_return_address(7); break;
      case 7: ctx->addresses[i] = __builtin_return_address(8); break;
      case 8: ctx->addresses[i] = __builtin_return_address(9); break;
      case 9: ctx->addresses[i] = __builtin_return_address(10); break;
      case 10: ctx->addresses[i] = __builtin_return_address(11); break;
      case 11: ctx->addresses[i] = __builtin_return_address(12); break;
      case 12: ctx->addresses[i] = __builtin_return_address(13); break;
      case 13: ctx->addresses[i] = __builtin_return_address(14); break;
      case 14: ctx->addresses[i] = __builtin_return_address(15); break;
      case 15: ctx->addresses[i] = __builtin_return_address(16); break;

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
  asan_giovese_populate_context(ctx);
  asan_giovese_alloc_insert(&data[16], &data[16 + 10], ctx);

  void*          pc = get_pc();
  register void* sp asm("rsp");
  register void* bp asm("rbp");

  const int IDX = 16;

  printf("<test> accessing %p\n", &data[IDX]);

  if (asan_giovese_loadN(&data[IDX], 11))
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, &data[IDX], 11, &data[IDX],
                                  pc, bp, sp);

}

