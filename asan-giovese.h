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

#ifndef __ASAN_GIOVESE_H__
#define __ASAN_GIOVESE_H__

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>

#ifndef TARGET_ULONG
#define TARGET_ULONG uintptr_t
#endif

#define HIGH_SHADOW_ADDR ((void*)0x02008fff7000ULL)
#define LOW_SHADOW_ADDR ((void*)0x00007fff8000ULL)

#define HIGH_SHADOW_SIZE (0xdfff0000fffULL)
#define LOW_SHADOW_SIZE (0xfffefffULL)

#define SHADOW_OFFSET (0x7fff8000ULL)

/* shadow map byte values */
#define ASAN_VALID 0x00
#define ASAN_PARTIAL1 0x01
#define ASAN_PARTIAL2 0x02
#define ASAN_PARTIAL3 0x03
#define ASAN_PARTIAL4 0x04
#define ASAN_PARTIAL5 0x05
#define ASAN_PARTIAL6 0x06
#define ASAN_PARTIAL7 0x07
#define ASAN_ARRAY_COOKIE 0xac
#define ASAN_STACK_RZ 0xf0
#define ASAN_STACK_LEFT_RZ 0xf1
#define ASAN_STACK_MID_RZ 0xf2
#define ASAN_STACK_RIGHT_RZ 0xf3
#define ASAN_STACK_FREED 0xf5
#define ASAN_STACK_OOSCOPE 0xf8
#define ASAN_GLOBAL_RZ 0xf9
#define ASAN_HEAP_RZ 0xe9
#define ASAN_USER 0xf7
#define ASAN_HEAP_LEFT_RZ 0xfa
#define ASAN_HEAP_RIGHT_RZ 0xfb
#define ASAN_HEAP_FREED 0xfd

enum {

  ACCESS_TYPE_LOAD,
  ACCESS_TYPE_STORE,

};

struct call_context {

  TARGET_ULONG* addresses;
  uint16_t      size;
  uint16_t      tid;

};

struct chunk_info {

  TARGET_ULONG         start;
  TARGET_ULONG         end;
  struct call_context* alloc_ctx;
  struct call_context* free_ctx;  // NULL if chunk is allocated

};

extern void* __ag_high_shadow;
extern void* __ag_low_shadow;

void  asan_giovese_populate_context(struct call_context* ctx, TARGET_ULONG pc);
char* asan_giovese_printaddr(TARGET_ULONG guest_addr);

void asan_giovese_init(void);

int asan_giovese_load1(void* addr);
int asan_giovese_load2(void* addr);
int asan_giovese_load4(void* addr);
int asan_giovese_load8(void* addr);
int asan_giovese_store1(void* addr);
int asan_giovese_store2(void* addr);
int asan_giovese_store4(void* addr);
int asan_giovese_store8(void* addr);
int asan_giovese_loadN(void* addr, size_t n);
int asan_giovese_storeN(void* addr, size_t n);

void asan_giovese_poison_region(void const volatile* addr, size_t n,
                                uint8_t poison_byte);
void asan_giovese_user_poison_region(void const volatile* addr, size_t n);
void asan_giovese_unpoison_region(void const volatile* addr, size_t n);

void asan_giovese_report_and_crash(int access_type, void* addr, size_t n,
                                   TARGET_ULONG guest_addr, TARGET_ULONG pc,
                                   TARGET_ULONG bp, TARGET_ULONG sp);

struct chunk_info* asan_giovese_alloc_search(TARGET_ULONG query);
void asan_giovese_alloc_insert(TARGET_ULONG start, TARGET_ULONG end,
                               struct call_context* alloc_ctx);

#endif

