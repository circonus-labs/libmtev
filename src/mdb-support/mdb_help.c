/*
 * Copyright (c) 2014-2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name Circonus, Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
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

#include <sys/mdb_modapi.h>

typedef struct mdb_modinfo_var {
        ushort_t mi_dvers;
        mdb_dcmd_t *mi_dcmds;
        mdb_walker_t *mi_walkers;
} mdb_modinfo_var_t;

#define MAX_MDB_STUFF 1024
static mdb_dcmd_t _static_mi_dcmds[MAX_MDB_STUFF];
static mdb_walker_t _static_mi_walkers[MAX_MDB_STUFF];

static mdb_modinfo_var_t _one_true_modinfo = {
  .mi_dvers = MDB_API_VERSION,
  .mi_dcmds = _static_mi_dcmds,
  .mi_walkers = _static_mi_walkers
};

const mdb_modinfo_t *_mdb_accum(const mdb_modinfo_t *toadd) {
  int i, dcmd_cnt = 0, new_dcmd_cnt = 0;
  int walker_cnt = 0, new_walker_cnt = 0;
 
  if(_one_true_modinfo.mi_dcmds) while(_one_true_modinfo.mi_dcmds[dcmd_cnt++].dc_name);
  if(dcmd_cnt>0) dcmd_cnt--;
  if(toadd->mi_dcmds) while(toadd->mi_dcmds[new_dcmd_cnt++].dc_name);
  if(new_dcmd_cnt>0) new_dcmd_cnt--;

  if(new_dcmd_cnt > 0) {
    for(i=0;i<new_dcmd_cnt;i++) {
      if((i+dcmd_cnt+1) >= MAX_MDB_STUFF) mdb_warn("too many dcmds");
      else {
        memcpy(&_one_true_modinfo.mi_dcmds[dcmd_cnt+i], &toadd->mi_dcmds[i], sizeof(mdb_dcmd_t));
      }
    }
  }

  if(_one_true_modinfo.mi_walkers) while(_one_true_modinfo.mi_walkers[walker_cnt++].walk_name);
  if(walker_cnt>0) walker_cnt--;
  if(toadd->mi_walkers) while(toadd->mi_walkers[new_walker_cnt++].walk_name);
  if(new_walker_cnt>0) new_walker_cnt--;

  if(new_walker_cnt > 0) {
    for(i=0;i<new_walker_cnt;i++) {
      if((i+walker_cnt+1) >= MAX_MDB_STUFF) mdb_warn("too many walkers");
      else {
        memcpy(&_one_true_modinfo.mi_walkers[walker_cnt+i], &toadd->mi_walkers[i], sizeof(mdb_walker_t));
      }
    }
  }

  return (mdb_modinfo_t *)&_one_true_modinfo;
}

int _print_addr_cb(uintptr_t addr, const void *u, void *data) {
  mdb_printf("%p\n", addr);
  return WALK_NEXT;
}
