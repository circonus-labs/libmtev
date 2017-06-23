/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#include "mtev_waterlevel.h"
#include "mtev_log.h"
#include <ck_pr.h>
#include <stdint.h>

#define MTEV_WATERLEVEL_CROSS_SENTINEL (INT_MIN)

struct _mtev_waterlevel_t
{
  int cur;
  /* threshold to cross to toggle enabled/disabled status. threshold will assume one of three
   * values:
   *  - high, meaning that the waterlevel is ENABLED, and crossing the threshold will disable;
   *  - low, meaning that the waterlevel is DISABLED, and crossing the threshold will enable;
   *  - MTEV_WATERLEVEL_CROSS_SENTINEL, meaning that we've _signalled_
   *    that the waterlevel should be disabled, and are waiting for
   *    the user to ack.
   */
  int cross;
  int low;
  int high;
};

mtev_waterlevel_t *mtev_waterlevel_create(int low, int high)
{
  mtev_waterlevel_t *wl = calloc(1, sizeof(mtev_waterlevel_t));
  /* start out enabled, so we must cross the high-water-mark to toggle status */
  wl->cross = high;
  wl->low = low;
  wl->high = high;
  return wl;
}

mtev_waterlevel_toggle_t mtev_waterlevel_adjust(mtev_waterlevel_t *wl, int by)
{
  int old_val;
  int new_val;

  do {
    old_val = ck_pr_load_int(&wl->cur);
    new_val = old_val+by;
  } while (ck_pr_cas_int(&wl->cur, old_val, new_val) == false);
  
  if (new_val >= wl->high) {
    if (ck_pr_cas_int(&wl->cross, wl->high, MTEV_WATERLEVEL_CROSS_SENTINEL))
      return MTEV_WATERLEVEL_TOGGLE_DISABLE;
  }
  else if (new_val <= wl->low) {
    if (ck_pr_cas_int(&wl->cross, wl->low, MTEV_WATERLEVEL_CROSS_SENTINEL))
      return MTEV_WATERLEVEL_TOGGLE_ENABLE;
  }
  return MTEV_WATERLEVEL_TOGGLE_KEEP;
}

mtev_waterlevel_toggle_t mtev_waterlevel_ack(mtev_waterlevel_t *wl, mtev_waterlevel_toggle_t t)
{
  mtevAssert(wl->cross == MTEV_WATERLEVEL_CROSS_SENTINEL);
  switch (t) {
    case MTEV_WATERLEVEL_TOGGLE_DISABLE:
      ck_pr_cas_int(&wl->cross, MTEV_WATERLEVEL_CROSS_SENTINEL, wl->low);
      break;
    case MTEV_WATERLEVEL_TOGGLE_ENABLE:
      ck_pr_cas_int(&wl->cross, MTEV_WATERLEVEL_CROSS_SENTINEL, wl->high);
    default:
      break;
  }
  /* Value _was_ across the threshold, but it's possible that it's
   * already crossed to the other threshold, in which case we might
   * need to toggle again. */
  return mtev_waterlevel_adjust(wl, 0);
}
