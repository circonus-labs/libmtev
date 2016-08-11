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


#include <mtev_thread.h>
#include <mtev_log.h>
#include <unistd.h>

#ifdef __sun
#include <sys/processor.h>
#endif
#if defined(linux) || defined(__linux) || defined(__linux__)
#define _GNU_SOURCE
#include <sched.h>

#ifndef gettid
static pid_t
gettid(void)
{
  return syscall(__NR_gettid);
}
#endif /* gettid */
#endif

static uint32_t mtev_current_cpu;
static __thread mtev_boolean mtev_thread_is_bound = mtev_false;

mtev_boolean
mtev_thread_bind_to_cpu(int cpu)
{
#ifdef __sun 
  if (processor_bind(P_LWPID, P_MYID, cpu, 0)) {
    mtevL(mtev_error, "Warning: Binding thread to cpu %d failed\n", cpu);
  }
  else {
    mtev_thread_is_bound = mtev_true;
    mtevL(mtev_debug, "Bound to CPU %i\n", cpu);
  }
#endif

#if defined(linux) || defined(__linux) || defined(__linux__)
  cpu_set_t s;
  CPU_ZERO(&s);
  CPU_SET(cpu, &s)
  int x = sched_setaffinity(gettid(), sizeof(s), &s);
  if (x == 0) {
    mtev_thread_is_bound = mtev_true;
    mtevL(mtev_debug, "Bound to CPU %i\n", cpu);
  } else {
    mtevL(mtev_error, "Warning: Binding thread to cpu %d failed\n", cpu);
  }   
#endif

  /* if we were able to bind, set the clock */
  if (mtev_thread_is_bound == mtev_true) {
    mtev_time_start_tsc(cpu);
  }

  return mtev_thread_is_bound;
}

mtev_boolean
mtev_thread_unbind_from_cpu(void)
{
#ifdef __sun 
  if (processor_bind(P_LWPID, P_MYID, PBIND_NONE, 0)) {
    mtevL(mtev_error, "Warning: Unbinding thread from cpus failed\n");
  }
  else {
    mtev_thread_is_bound = mtev_false;
    mtevL(mtev_debug, "Unbound from CPUs\n");
  }
#endif

#if defined(linux) || defined(__linux) || defined(__linux__)
  cpu_set_t s;
  CPU_ZERO(&s);
  int x = sched_setaffinity(gettid(), sizeof(s), &s);
  if (x == 0) {
    mtev_thread_is_bound = mtev_false;
    mtevL(mtev_debug, "Unbound from CPUs\n");
  } else {
    mtevL(mtev_error, "Warning: Unbinding thread from cpus failed\n");
  }   
#endif

  if (mtev_thread_is_bound == mtev_false) {
    mtev_time_stop_tsc(0);
  }
  return mtev_thread_is_bound == mtev_false;
}


struct mtev_thread_closure {
  void *(*start_routine)(void *);
  void *arg;
};

static void * 
mtev_thread_start_routine(void *arg) {
  struct mtev_thread_closure *c = arg;
  mtev_thread_init();
  void *rval = c->start_routine(c->arg);
  free(c);
  return rval;
}

int
mtev_thread_create(pthread_t *thread, const pthread_attr_t *attr,
                     void *(*start_routine) (void *), void *arg)
{
  struct mtev_thread_closure *c = malloc(sizeof(struct mtev_thread_closure));
  c->start_routine = start_routine;
  c->arg = arg;
  return pthread_create(thread, attr, mtev_thread_start_routine, c);
}

void
mtev_thread_init() 
{  
  long nrcpus = sysconf(_SC_NPROCESSORS_ONLN);
  int cpu = ck_pr_faa_uint(&mtev_current_cpu, 1) % nrcpus;
  mtev_thread_bind_to_cpu(cpu);
}

mtev_boolean
mtev_thread_is_bound_to_cpu() 
{
  return mtev_thread_is_bound;
}
