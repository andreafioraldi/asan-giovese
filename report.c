#include "asan-giovese.h"
#include <stdio.h>
#include <unistd.h>

#define DEFAULT_REDZONE_SIZE 32

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
  asan_giovese_populate_context(&ctx);
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

