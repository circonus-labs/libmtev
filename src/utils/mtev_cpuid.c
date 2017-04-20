/*
 * Copyright (c) 2016, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name Circonus, Inc. nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "mtev_cpuid.h"

#define BIT(b) (1ULL << (b))

struct cpuid {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
} __attribute__((packed));

enum {
  VENDOR_INTEL,
  VENDOR_AMD,
  VENDOR_UNKNOWN,
  VENDOR_LENGTH
};

static inline void
mtev_cpuid(struct cpuid *r, uint32_t eax)
{

  __asm__ __volatile__("cpuid"
                       : "=a" (r->eax),
                         "=b" (r->ebx),
                         "=c" (r->ecx),
                         "=d" (r->edx)
                       : "a"  (eax)
                       : "memory");

  return;
}

static inline int
mtev_cpu_vendor(void)
{
  struct cpuid id;
  
  mtev_cpuid(&id, 0);
  if (id.ebx == 0x756E6547 && id.ecx == 0x6C65746E && id.edx == 0x49656E69) 
    return VENDOR_INTEL;
  else if (id.ebx == 0x68747541 && id.ecx == 0x444D4163 && id.edx == 0x69746E65) 
    return VENDOR_AMD;
  return VENDOR_UNKNOWN;
}

mtev_boolean
mtev_cpuid_feature(int feature)
{
  struct cpuid id;
  uint64_t features;
  int vendor;

  if (feature < 0 || feature >= MTEV_CPU_FEATURE_LENGTH)
    return mtev_false;

  vendor = mtev_cpu_vendor();

  if (feature == MTEV_CPU_FEATURE_INVARIANT_TSC) {
    mtev_cpuid(&id, 0x80000007);
    return (BIT(8) & id.edx) ? mtev_true : mtev_false;
  }

  if (feature == MTEV_CPU_FEATURE_RDTSC) {
    if (vendor != VENDOR_INTEL) {
      return mtev_false;
    }
    mtev_cpuid(&id, 1);
    features = ((uint64_t)id.ecx << 32) | id.edx;
    return (BIT(4) & features) != 0 ? mtev_true : mtev_false;
  }

  if (feature == MTEV_CPU_FEATURE_RDTSCP) {
    if (vendor != VENDOR_INTEL) {
      return mtev_false;
    }

    mtev_cpuid(&id, 0x80000001);

    return (id.edx & BIT(27)) != 0 ? mtev_true : mtev_false;
  }
  return mtev_false;
}
