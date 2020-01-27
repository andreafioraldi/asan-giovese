#include "asan-giovese.h"
#include <sys/mman.h>
#include <assert.h>

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

