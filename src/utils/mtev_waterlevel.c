/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#include "mtev_waterlevel.h"
#include "mtev_log.h"
#include <ck_pr.h>
#include <stdint.h>

#define MTEV_WATERLEVEL_STATE_ENABLED 0
#define MTEV_WATERLEVEL_STATE_DISABLING 1
#define MTEV_WATERLEVEL_STATE_DISABLED 2
#define MTEV_WATERLEVEL_STATE_ENABLING 3

struct _mtev_waterlevel_t
{
  int cur;
  int state;
  int low;
  int high;
};

mtev_waterlevel_t *mtev_waterlevel_create(int low, int high)
{
  mtev_waterlevel_t *wl = calloc(1, sizeof(mtev_waterlevel_t));
  wl->state = MTEV_WATERLEVEL_STATE_ENABLED;
  wl->low = low;
  wl->high = high;
  return wl;
}

static mtev_waterlevel_toggle_t
mtev_waterlevel_adjust_up(mtev_waterlevel_t *wl, unsigned int adjustment)
{
  int signed_adjustment = (int) adjustment;
  int old_val;

  do {
    old_val = ck_pr_load_int(&wl->cur);
    if (old_val == wl->high) {
      if (ck_pr_cas_int(&wl->state, MTEV_WATERLEVEL_STATE_ENABLED,
                        MTEV_WATERLEVEL_STATE_DISABLING))
        return MTEV_WATERLEVEL_TOGGLE_DISABLE;
      else
        return MTEV_WATERLEVEL_TOGGLE_DISABLED;
    }
  } while (ck_pr_cas_int(&wl->cur, old_val, old_val+signed_adjustment) == false);
  return MTEV_WATERLEVEL_TOGGLE_KEEP;
}

mtev_waterlevel_toggle_t mtev_waterlevel_raise_one(mtev_waterlevel_t *wl)
{
  return mtev_waterlevel_adjust_up(wl, 1);
}

mtev_waterlevel_toggle_t mtev_waterlevel_lower(mtev_waterlevel_t *wl, unsigned int by)
{
  int signed_adjustment = -1 * ((int) by);
  int old_val;
  int new_val;

  do {
    old_val = ck_pr_load_int(&wl->cur);
    new_val = old_val+signed_adjustment;
  } while (ck_pr_cas_int(&wl->cur, old_val, new_val) == false);
  if (new_val < wl->low) {
    if (ck_pr_cas_int(&wl->state, MTEV_WATERLEVEL_STATE_DISABLED, MTEV_WATERLEVEL_STATE_ENABLING))
      return MTEV_WATERLEVEL_TOGGLE_ENABLE;
  }
  return MTEV_WATERLEVEL_TOGGLE_KEEP;
}

mtev_waterlevel_toggle_t mtev_waterlevel_ack(mtev_waterlevel_t *wl, mtev_waterlevel_toggle_t t)
{
  switch (t) {
    case MTEV_WATERLEVEL_TOGGLE_DISABLE:
      mtevEvalAssert(ck_pr_cas_int(&wl->state, MTEV_WATERLEVEL_STATE_DISABLING,
                                   MTEV_WATERLEVEL_STATE_DISABLED));
      return mtev_waterlevel_lower(wl, 0);

    case MTEV_WATERLEVEL_TOGGLE_ENABLE:
      mtevEvalAssert(ck_pr_cas_int(&wl->state,
                                   MTEV_WATERLEVEL_STATE_ENABLING,
                                   MTEV_WATERLEVEL_STATE_ENABLED));
      return mtev_waterlevel_adjust_up(wl, 0);
    default:
      break;
  }
  return MTEV_WATERLEVEL_TOGGLE_KEEP;
}
