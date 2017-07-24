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
#include <mtev_time.h>
#include <mtev_log.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#if defined(__MACH__)
#include <mach/mach_init.h>
#include <mach/thread_policy.h>

kern_return_t  thread_policy_set(
                         thread_t                      thread,
                         thread_policy_flavor_t        flavor,
                         thread_policy_t                    policy_info,
                         mach_msg_type_number_t        count);
#endif
#ifdef __sun
#include <sys/processor.h>
#include <sys/priocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/fsspriocntl.h>
#endif
#if defined(linux) || defined(__linux) || defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <sys/syscall.h>

#ifndef gettid
static uint32_t
getthreadid(void)
{
  return syscall(__NR_gettid);
}
#endif
#else
static uint32_t
getthreadid(void)
{
  return (uint32_t)(uintptr_t)pthread_self();
}
#endif

static uint32_t mtev_current_cpu;
static __thread mtev_boolean mtev_thread_is_bound = mtev_false;
static __thread uint32_t mtev_current_thread_id;
static mtev_boolean mtev_disable_binding = mtev_false;

uint32_t
mtev_thread_id(void) {
  if(!mtev_current_thread_id) mtev_current_thread_id = getthreadid();
  return mtev_current_thread_id;
}

mtev_boolean
mtev_thread_bind_to_cpu(int cpu)
{
#ifdef __sun 
#ifdef RUNNING_ON_VALGRIND
  if (RUNNING_ON_VALGRIND != 0) {
    mtevL(mtev_error, "Warning: Binding prevented under valgrind\n");
    return mtev_thread_is_bound;
  }
#endif
  if (processor_bind(P_LWPID, P_MYID, cpu, 0)) {
    mtevL(mtev_error, "Warning: Binding thread to cpu %d failed\n", cpu);
  }
  else {
    mtev_thread_is_bound = mtev_true;
    //mtevL(mtev_debug, "Bound to CPU %i\n", cpu);
  }
#endif

#if defined(linux) || defined(__linux) || defined(__linux__)
  cpu_set_t s;
  CPU_ZERO(&s);
  CPU_SET(cpu, &s);
  int x = sched_setaffinity(getthreadid(), sizeof(s), &s);
  if (x == 0) {
    mtev_thread_is_bound = mtev_true;
    //mtevL(mtev_debug, "Bound to CPU %i\n", cpu);
  } else {
    mtevL(mtev_error, "Warning: Binding thread to cpu %d failed\n", cpu);
  }   
#endif

#if defined(__MACH__)
  thread_affinity_policy_data_t policy = { cpu };
  thread_port_t mach_thread = mach_thread_self();
  if(thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY,
                       (thread_policy_t)&policy, 1) == KERN_SUCCESS) {
    mtev_thread_is_bound = mtev_true;
    sched_yield();
  } else {
    mtevL(mtev_error, "mach:thread_policy_set -> %s\n", strerror(errno));
  }
#endif
  return mtev_thread_is_bound;
}

mtev_boolean
mtev_thread_unbind_from_cpu(void)
{
#ifdef __sun 
#ifdef RUNNING_ON_VALGRIND
  if (RUNNING_ON_VALGRIND != 0) {
    mtevL(mtev_error, "Warning: Unbinding prevented under valgrind\n");
    return mtev_thread_is_bound;
  }
#endif
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
  int x = sched_setaffinity(getthreadid(), sizeof(s), &s);
  if (x == 0) {
    mtev_thread_is_bound = mtev_false;
    mtevL(mtev_debug, "Unbound from CPUs\n");
  } else {
    mtevL(mtev_error, "Warning: Unbinding thread from cpus failed\n");
  }   
#endif

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
mtev_thread_init(void)
{  
  if (mtev_disable_binding == mtev_true) {
    return;
  }
  long nrcpus = sysconf(_SC_NPROCESSORS_ONLN);
  int cpu = ck_pr_faa_uint(&mtev_current_cpu, 1) % nrcpus;
  mtev_thread_bind_to_cpu(cpu);
}

mtev_boolean
mtev_thread_prio(int prio) {
#ifdef __sun
  pcinfo_t pcinfo;
  if (priocntl(P_LWPID, P_MYID, PC_GETXPARMS, NULL,
         PC_KY_CLNAME, pcinfo.pc_clname, 0) == -1 ||
         priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1) {
    mtevL(mtev_debug, "priocntl(P_LWPID, P_MYID, PC_GETPARMS, ...) -> %s\n",
          strerror(errno));
    return mtev_false;
  }
  int key_id = 0;
  if(!strcmp(pcinfo.pc_clname, "FSS")) {
    fssinfo_t *fssinfo = (fssinfo_t *)pcinfo.pc_clinfo;
    pri_t maxupri = fssinfo->fss_maxupri;
    if(prio > maxupri) prio = maxupri;
    if(prio < -maxupri) prio = -maxupri;
    key_id = FSS_KY_UPRI;
  }
  else if(!strcmp(pcinfo.pc_clname, "RT")) {
    rtinfo_t *rtinfo = (rtinfo_t *)pcinfo.pc_clinfo;
    pri_t maxpri = rtinfo->rt_maxpri;
    if(prio > maxpri) prio = maxpri;
    if(prio < 0) prio = 0;
    key_id = RT_KY_PRI;
  }
  else {
    mtevL(mtev_debug, "Unknown schedule class: %s\n", pcinfo.pc_clname);
    return mtev_false;
  }
  if(priocntl(P_LWPID, P_MYID, PC_SETXPARMS, pcinfo.pc_clname,
              key_id, prio, NULL) == -1) {
      mtevL(mtev_debug, "Failed to set %d/%d priority to %s/%d: %s\n",
            (int)getpid(), (int)_lwp_self(), pcinfo.pc_clname, prio,
            strerror(errno));
      return mtev_false;
    }
  mtevL(mtev_debug, "%d/%d priority to %s/%d.\n",
        (int)getpid(), (int)_lwp_self(), pcinfo.pc_clname, prio);
  return mtev_true;
#else
  int err, sched;
  struct sched_param sp;
  if((err = pthread_getschedparam(pthread_self(), &sched, &sp)) != 0) {
    mtevL(mtev_debug, "mtev_thread_prio cannot get sched params: %s\n", strerror(err));
    return false;
  }
  sp.sched_priority = prio;
  int maxprio = sched_get_priority_max(sched);
  int minprio = sched_get_priority_min(sched);
  if(sp.sched_priority > maxprio) sp.sched_priority = maxprio;
  else if(sp.sched_priority < minprio) sp.sched_priority = minprio;
  if((err = pthread_setschedparam(pthread_self(), sched, &sp)) != 0) {
    mtevL(mtev_debug, "mtev_thread_prio(%d / %d): %d/%s\n", prio, sp.sched_priority, err, strerror(err));
    return mtev_false;
  }
  mtevL(mtev_debug, "%d/%d priority to %d/%d.\n",
        (int)getpid(), (int)(intptr_t)pthread_self(), sched, sp.sched_priority);
  return mtev_true;
#endif
}

mtev_boolean
mtev_thread_realtime(uint64_t qns) {
#ifdef __sun
  pcinfo_t pcinfo;
  pcparms_t pcparms;
  memcpy(pcinfo.pc_clname, "RT", 3);
  if (priocntl((idtype_t) 0, (id_t) 0, PC_GETCID, (caddr_t)&pcinfo) == -1) {
    mtevL(mtev_stderr, "No realtime scheduling class available.\n");
    return mtev_false;
  }
  pcparms.pc_cid = pcinfo.pc_cid;
  ((rtparms_t *)pcparms.pc_clparms)->rt_pri = 59;
  if(qns == UINT64_MAX) {
    ((rtparms_t *)pcparms.pc_clparms)->rt_tqnsecs = RT_TQINF;
  } else if(qns == 0) {
    ((rtparms_t *)pcparms.pc_clparms)->rt_tqnsecs = RT_TQDEF;
  } else {
    ((rtparms_t *)pcparms.pc_clparms)->rt_tqnsecs = qns % 1000000000;
    ((rtparms_t *)pcparms.pc_clparms)->rt_tqsecs = qns / 1000000000;
  }
  if (priocntl(P_LWPID, P_MYID, PC_SETPARMS, (caddr_t)&pcparms) == -1) {
    mtevL(mtev_debug, "Failed changing thread %d/%d to %s scheduling class: %s.\n",
          (int)getpid(), (int)_lwp_self(), pcinfo.pc_clname, strerror(errno));
    return mtev_false;
  }
  mtevL(mtev_debug, "%d/%d -> %s scheduling class\n",
        (int)getpid(), (int)_lwp_self(), pcinfo.pc_clname);
  return mtev_true;
#elif defined(linux) || defined(__linux) || defined(__linux__)
  int err;
  struct sched_param sp;
  sp.sched_priority = sched_get_priority_max(SCHED_RR);
  if((err = pthread_setschedparam(pthread_self(), SCHED_RR, &sp)) != 0) {
    mtevL(mtev_debug, "Failed changing thread %d/%d to %s scheduling class: %d/%s.\n",
          (int)getpid(), (int)getthreadid(), "SCHED_RR", err, strerror(err));
    return mtev_false;
  }
  mtevL(mtev_debug, "%d/%d -> %s scheduling class\n",
        (int)getpid(), (int)getthreadid(), "SCHED_RR");
  return mtev_true;
#else
  return mtev_false;
#endif
}

void
mtev_thread_disable_binding(void)
{
  mtev_disable_binding = mtev_true;
}

mtev_boolean
mtev_thread_is_bound_to_cpu(void)
{
  return mtev_thread_is_bound;
}

