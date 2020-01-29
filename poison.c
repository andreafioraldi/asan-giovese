#include "asan-giovese.h"

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

  int8_t*   shadow_addr;
  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;

  while (start < end) {

    uint8_t* shadow_addr = (uint8_t*)(start >> 3) + SHADOW_OFFSET;
    *shadow_addr = 0;
    start += 8;

  }

}

