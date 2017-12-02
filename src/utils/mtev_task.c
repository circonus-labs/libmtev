/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
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

#include "mtev_defines.h"
#include "mtev_log.h"
#include "mtev_task.h"
#include "eventer/eventer.h"

static int task_ctx_idx = -1;

uint64_t mtev_task_get_current_task(eventer_t e) {
  if(task_ctx_idx < 0) return 0;
  if(e == NULL) e = eventer_get_this_event();
  if(e == NULL) return 0;
  return (uint64_t)(uintptr_t)eventer_get_context(e, task_ctx_idx);
}

void mtev_task_set_current_task(eventer_t e, uint64_t taskid) {
  if(task_ctx_idx < 0) return;
  if(e == NULL) e = eventer_get_this_event();
  if(e == NULL) return;
  eventer_set_context(e, task_ctx_idx, (void *)(uintptr_t)taskid);
}

static eventer_t task_eventer_init(eventer_t e) {
  eventer_t parent;
  void *pctx;
  if(task_ctx_idx < 0) return e;
  if(NULL == (parent = eventer_get_this_event())) return e;
  pctx = eventer_get_context(parent, task_ctx_idx);
  eventer_set_context(e, task_ctx_idx, pctx);
  return e;
}
static void task_eventer_deinit(eventer_t e) {
  (void)e;
  return;
}
static void task_eventer_copy(eventer_t tgt, const eventer_t src) {
  void *ctx;
  if(task_ctx_idx < 0) return;
  ctx = eventer_get_context(src, task_ctx_idx);
  eventer_set_context(tgt, task_ctx_idx, ctx);
}
eventer_context_opset_t task_eventer_context_ops = {
  .eventer_t_init = task_eventer_init,
  .eventer_t_deinit = task_eventer_deinit,
  .eventer_t_copy = task_eventer_copy,
  .eventer_t_callback_prep = NULL,
  .eventer_t_callback_cleanup = NULL
};

void mtev_task_eventer_init(void) {
  if(task_ctx_idx >= 0) return;
  task_ctx_idx = eventer_register_context("task", &task_eventer_context_ops);
  mtevL(mtev_debug, "eventer task contexts %s\n",
        (task_ctx_idx < 0) ? "failed to register" : "registered");
}
