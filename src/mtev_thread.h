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

#ifndef MTEV_THREAD_H
#define MTEV_THREAD_H

#include <mtev_defines.h>
#include <pthread.h>

/**
 * wrapper for pthread_create which performs socket affinity by round robin placing
 * threads onto cores.
 */
API_EXPORT(int)
  mtev_thread_create(pthread_t *thread, const pthread_attr_t *attr,
                     void *(*start_routine) (void *), void *arg);

/**
 * Binds the currently executing thread (LWP) to the numbered CPU
 */
API_EXPORT(mtev_boolean)
  mtev_thread_bind_to_cpu(int cpu);

/**
 * Unbinds the currently executing thread (LWP) from any specific CPU.
 * Gives it free rain over any processor.
 */
API_EXPORT(mtev_boolean)
  mtev_thread_unbind_from_cpu(void);

  /**
   * returns mtev_true if this LWP has been bound to a cpu already
   */
API_EXPORT(mtev_boolean)
  mtev_thread_is_bound_to_cpu(void);

/**
 * convenience function if you call pthread_create yourself.  Call this function
 * from within the spawned thread to affine it to the next CPU in tracked sequence
 */
API_EXPORT(void)
  mtev_thread_init(void);

/**
 * wrapper for name setting (if supported)
 */
API_EXPORT(void)
  mtev_thread_setname(const char *);

/**
 * attempt to schedule as a real-time process within the system.
 * nqt is the request scheduling quantum in nanoseconds. If the OS
 * does not support setting the quantum, the arugment is ignored.
 */
API_EXPORT(mtev_boolean)
  mtev_thread_realtime(uint64_t nqt);

/**
 * attempt to set the current thread's priority in its scheduling class
 */
API_EXPORT(mtev_boolean)
  mtev_thread_prio(int prio);

/**
 * Switches off and disallows binding of threads to cores. If you call this on startup,
 * mtev_thread_init and mtev_thread_create will not bind the current LWP to the next core
 * in sequence.  They will silently noop.
 */
API_EXPORT(void)
  mtev_thread_disable_binding(void);

API_EXPORT(uint32_t)
  mtev_thread_id(void);

#endif
