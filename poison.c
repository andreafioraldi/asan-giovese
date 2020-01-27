#include "asan-giovese.h"

int asan_giovese_load1(void* addr) {

  byte* shadow_addr = (byte*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  byte  k = *shadow_addr;
  return (k != 0 && (((uintptr_t)addr & 7) + 1 > k));

}

int asan_giovese_load2(void* addr) {

  byte* shadow_addr = (byte*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  byte  k = *shadow_addr;
  return (k != 0 && (((uintptr_t)addr & 7) + 2 > k));

}

int asan_giovese_load4(void* addr) {

  byte* shadow_addr = (byte*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  byte  k = *shadow_addr;
  return (k != 0 && (((uintptr_t)addr & 7) + 4 > k));

}

int asan_giovese_load8(void* addr) {

  byte* shadow_addr = (byte*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  return (*shadow_addr);

}

int asan_giovese_store1(void* addr) {

  byte* shadow_addr = (byte*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  byte  k = *shadow_addr;
  return (k != 0 && (((uintptr_t)addr & 7) + 1 > k));

}

int asan_giovese_store2(void* addr) {

  byte* shadow_addr = (byte*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  byte  k = *shadow_addr;
  return (k != 0 && (((uintptr_t)addr & 7) + 2 > k));

}

int asan_giovese_store4(void* addr) {

  byte* shadow_addr = (byte*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  byte  k = *shadow_addr;
  return (k != 0 && (((uintptr_t)addr & 7) + 4 > k));

}

int asan_giovese_store8(void* addr) {

  byte* shadow_addr = (byte*)((uintptr_t)addr >> 3) + SHADOW_OFFSET;
  return (*shadow_addr);

}

int asan_giovese_loadN(void* addr, size_t n) {

  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;
  uintptr_t last_8 = end;
  if (end & 0x7) last_8 = ((end - 8) & 7) + 1;

  if (start & 0x7) {

    uintptr_t next_8 = (start | 7) + 1;
    size_t    first_size = next_8 - start;

    if (n <= first_size) {

      byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
      byte  k = *shadow_addr;
      if (k != 0 && ((start & 7) + n > k)) return 1;
      return;

    }

    byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    byte  k = *shadow_addr;
    if (k != 0 && ((start & 7) + first_size > k)) return 1;

    start = next_8;

  }

  while (start < last_8) {

    byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    if (*shadow_addr) return 1;
    start += 8;

  }

  if (last_8 != end) {

    size_t last_size = end - last_8;
    byte*  shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    byte   k = *shadow_addr;
    if (k != 0 && ((start & 7) + last_size > k)) return 1;

  }

  return 0;

}

int asan_giovese_storeN(void* addr, size_t n) {

  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;
  uintptr_t last_8 = end;
  if (end & 0x7) last_8 = ((end - 8) & 7) + 1;

  if (start & 0x7) {

    uintptr_t next_8 = (start | 7) + 1;
    size_t    first_size = next_8 - start;

    if (n <= first_size) {

      byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
      byte  k = *shadow_addr;
      if (k != 0 && ((start & 7) + n > k)) return 1;
      return;

    }

    byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    byte  k = *shadow_addr;
    if (k != 0 && ((start & 7) + first_size > k)) return 1;

    start = next_8;

  }

  while (start < last_8) {

    byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    if (*shadow_addr) return 1;
    start += 8;

  }

  if (last_8 != end) {

    size_t last_size = end - last_8;
    byte*  shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    byte   k = *shadow_addr;
    if (k != 0 && ((start & 7) + last_size > k)) return 1;

  }

  return 0;

}

int asan_giovese_poison_region(void const volatile* addr, size_t n,
                               byte poison_byte) {

  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;
  uintptr_t last_8 = end;
  if (end & 0x7) last_8 = ((end - 8) & 7) + 1;

  if (start & 0x7) {

    uintptr_t next_8 = (start | 7) + 1;
    size_t    first_size = next_8 - start;

    if (n <= first_size) {

      byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
      *shadow_addr = n;
      return;

    }

    byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    *shadow_addr = first_size;

    start = next_8;

  }

  while (start < last_8) {

    byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    *shadow_addr = poison_byte;
    start += 8;

  }

  if (last_8 != end) {  // TODO

    size_t last_size = end - last_8;
    byte*  shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    *shadow_addr = last_size;

  }

}

int asan_giovese_user_poison_region(void const volatile* addr, size_t n) {

  asan_giovese_poison_region(addr, n, ASAN_USER);

}

int asan_giovese_unpoison_region(void const volatile* addr, size_t n) {

  byte*     shadow_addr;
  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;

  while (start < end) {

    byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    *shadow_addr = 0;
    start += 8;

  }

}

