#include "asan-giovese.h"
#include "pmparser.h"
#include <stdio.h>
#include <unistd.h>

const char* access_type_str[] = {"READ", "WRITE"};

const char* asan_giovese_strerror(byte poison_byte) {

  switch (poison_byte) {

    case ASAN_HEAP_RZ:
    case ASAN_HEAP_LEFT_RZ:
    case ASAN_HEAP_RIGHT_RZ: return "heap-buffer-overflow";
    case ASAN_HEAP_FREED: return "heap-use-after-free";

  }

  return "use-after-poison";

}

const char* asan_giovese_find_error(void* addr, size_t n, void** fault_addr) {

  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + n;

  while (start < end) {

    byte* shadow_addr = (byte*)(start >> 3) + SHADOW_OFFSET;
    switch (*shadow_addr) {

      case ASAN_VALID: break;
      case ASAN_PARTIAL1:
      case ASAN_PARTIAL2:
      case ASAN_PARTIAL3:
      case ASAN_PARTIAL4:
      case ASAN_PARTIAL5:
      case ASAN_PARTIAL6:
      case ASAN_PARTIAL7: {

        uintptr_t a =
            (((uintptr_t)shadow_addr - SHADOW_OFFSET) << 3) + *shadow_addr;
        if (*fault_addr == NULL && a >= start && a < end)
          *fault_addr = (void*)a;
        break;

      }

      default: {

        if (*fault_addr == NULL) *fault_addr = (void*)start;
        return asan_giovese_strerror(*shadow_addr);

      }

    }

    start += 8;

  }

  return "use-after-poison";

}

static void __print_shadow_line(byte* shadow_addr) {

  /*uintptr_t a = (uintptr_t)shadow_addr;
  if (!((a >= (uintptr_t)__ag_high_shadow && a < ((uintptr_t)__ag_high_shadow +
  HIGH_SHADOW_ADDR))
      || (a >= (uintptr_t) __ag_low_shadow && a < ((uintptr_t)__ag_low_shadow +
  LOW_SHADOW_ADDR)))) return;*/

  fprintf(stderr,
          "  0x%012" PRIxPTR
          ": %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
          "%02x %02x %02x\n",
          shadow_addr, shadow_addr[0], shadow_addr[1], shadow_addr[2],
          shadow_addr[3], shadow_addr[4], shadow_addr[5], shadow_addr[6],
          shadow_addr[7], shadow_addr[8], shadow_addr[9], shadow_addr[10],
          shadow_addr[11], shadow_addr[12], shadow_addr[13], shadow_addr[14],
          shadow_addr[15]);

}

static void __print_shadow_line_fault(byte* shadow_addr,
                                      byte* shadow_fault_addr) {

  /*uintptr_t a = (uintptr_t)shadow_addr;
  if (!((a >= (uintptr_t)__ag_high_shadow && a < ((uintptr_t)__ag_high_shadow +
  HIGH_SHADOW_ADDR))
      || (a >= (uintptr_t) __ag_low_shadow && a < ((uintptr_t)__ag_low_shadow +
  LOW_SHADOW_ADDR)))) return;*/

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

  fprintf(stderr, format, shadow_addr, shadow_addr[0], shadow_addr[1],
          shadow_addr[2], shadow_addr[3], shadow_addr[4], shadow_addr[5],
          shadow_addr[6], shadow_addr[7], shadow_addr[8], shadow_addr[9],
          shadow_addr[10], shadow_addr[11], shadow_addr[12], shadow_addr[13],
          shadow_addr[14], shadow_addr[15]);

}

static void __print_shadow(byte* shadow_addr) {

  uintptr_t center = (uintptr_t)shadow_addr & ~15;
  __print_shadow_line(center - 16 * 5);
  __print_shadow_line(center - 16 * 4);
  __print_shadow_line(center - 16 * 3);
  __print_shadow_line(center - 16 * 2);
  __print_shadow_line(center - 16);
  __print_shadow_line_fault(center, shadow_addr);
  __print_shadow_line(center + 16);
  __print_shadow_line(center + 16 * 2);
  __print_shadow_line(center + 16 * 3);
  __print_shadow_line(center + 16 * 4);
  __print_shadow_line(center + 16 * 5);

}

static char* __get_addr_mapping(void* addr) {

  procmaps_iterator* maps = pmparser_parse(-1);
  procmaps_struct*   maps_tmp = NULL;

  uintptr_t a = (uintptr_t)addr;

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
  return strdup("");

}

void asan_giovese_report_and_crash(int access_type, void* addr, size_t n,
                                   void* pc, void* bp, void* sp) {

  struct call_context ctx;
  asan_giovese_populate_context(&ctx);
  void*       fault_addr;
  const char* error_type = asan_giovese_find_error(addr, n, &fault_addr);

  fprintf(
      stderr,
      "=================================================================\n"
      "==%d==ERROR: AddressSanitizer: %s on address %p at pc %p bp %p sp %p\n",
      getpid(), error_type, addr, pc, bp, sp);

  fprintf(stderr, "%s of size %lu at %p thread T0\n",
          access_type_str[access_type], n, addr);
  size_t i;
  for (i = 0; i < ctx.size; ++i)
    fprintf(stderr, "    #%lu %p%s\n", i, ctx.addresses[i],
            __get_addr_mapping(ctx.addresses[i]));

  /*
  0x602000000035 is located 0 bytes to the right of 5-byte region
  [0x602000000030,0x602000000035) allocated by thread T0 here: #0 0x7f467ad86203
  in BufferedStackTrace
  /build/llvm-toolchain-8-bJQSSk/llvm-toolchain-8-8/projects/compiler-rt/lib/asan/../sanitizer_common/sanitizer_stacktrace.h:97:55
      #1 0x7f467ad86203 in __qasan_malloc
  /build/llvm-toolchain-8-bJQSSk/llvm-toolchain-8-8/projects/compiler-rt/lib/asan/asan_malloc_linux.cc:230
      #2 0x562bb35002ce in qasan_actions_dispatcher
  /home/andrea/Desktop/QASAN/qemu/accel/tcg/tcg-runtime.c:236:29

  SUMMARY: AddressSanitizer: heap-buffer-overflow
  (/home/andrea/Desktop/QASAN/qasan-qemu+0x728973) in _fini
  */
  fprintf(stderr,
          "SUMMARY: AddressSanitizer: %s%s\n"
          "Shadow bytes around the buggy address:\n",
          error_type, __get_addr_mapping(pc));

  __print_shadow(((uintptr_t)fault_addr >> 3) + SHADOW_OFFSET);

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

