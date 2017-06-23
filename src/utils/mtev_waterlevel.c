/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#include "mtev_waterlevel.h"
#include "mtev_log.h"
#include <ck_pr.h>

struct _mtev_waterlevel_t
{
  int cur;
  /* threshold to cross to toggle enabled/disabled status. threshold will assume one of three
   * values:
   *  - high, meaning that the waterlevel is ENABLED, and crossing the threshold will disable;
   *  - low, meaning that the waterlevel is DISABLED, and crossing the threshold will enable;
   *  - -1, meaning that we've _signalled_ that the waterlevel should be disabled, and are waiting
   *    for the user to ack.
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
    old_val = (volatile int) wl->cur;
    new_val = old_val+by;
  } while (ck_pr_cas_int(&wl->cur, old_val, new_val) == false);
  
  if (new_val >= wl->high) {
    if (ck_pr_cas_int(&wl->cross, wl->high, -1))
      return MTEV_WATERLEVEL_TOGGLE_DISABLE;
  }
  else if (new_val <= wl->low) {
    if (ck_pr_cas_int(&wl->cross, wl->low, -1))
      return MTEV_WATERLEVEL_TOGGLE_ENABLE;
  }
  return MTEV_WATERLEVEL_TOGGLE_KEEP;
}

mtev_waterlevel_toggle_t mtev_waterlevel_ack(mtev_waterlevel_t *wl, mtev_waterlevel_toggle_t t)
{
  mtevAssert(wl->cross == -1);
  switch (t) {
    case MTEV_WATERLEVEL_TOGGLE_DISABLE:
      /* Value _was_ above the "high" threshold, and caller has now
       * run something to disable inflow, so no new work will be
       * added. It's possible, though, that enough has drained that we
       * need to re-enable inflow. */
      ck_pr_cas_int(&wl->cross, -1, wl->low);
      if (wl->cur <= wl->low) {
        /* fell below threshold, so we should enable, now. however,
         * it's possible that someone else has already started to
         * enable. */
        if (ck_pr_cas_int(&wl->cross, wl->low, -1))
          return MTEV_WATERLEVEL_TOGGLE_ENABLE;
      }
      break;
    case MTEV_WATERLEVEL_TOGGLE_ENABLE:
      /* same logic as above, but with high/low swapped. */
      ck_pr_cas_int(&wl->cross, -1, wl->high);
      if (wl->cur >= wl->high) {
        if (ck_pr_cas_int(&wl->cross, wl->high, -1))
          return MTEV_WATERLEVEL_TOGGLE_DISABLE;
      }
    default:
      break;
  }
  return MTEV_WATERLEVEL_TOGGLE_KEEP;
}
