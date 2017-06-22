/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#include "mtev_waterlevel.h"
#include "mtev_log.h"

void mtev_waterlevel_init(mtev_waterlevel_t *wl, int32_t high, int32_t low)
{
  wl->cur = 0;
  wl->high = high;
  wl->low = low;
  /* start out enabled, so we must cross the high-water-mark to toggle status */
  wl->cross = high;
}

mtev_waterlevel_toggle_t mtev_waterlevel_adjust(mtev_waterlevel_t *wl, int32_t by)
{
  int32_t new_val;

  new_val = (int32_t) mtev_atomic_add32(&wl->cur, (mtev_atomic32_t) by);
  if (new_val >= wl->high) {
    if (mtev_atomic_cas32(&wl->cross, (mtev_atomic32_t) -1, wl->high) == wl->high)
      return MTEV_WATERLEVEL_TOGGLE_DISABLE;
  }
  else if (new_val <= wl->low) {
    if (mtev_atomic_cas32(&wl->cross, (mtev_atomic32_t) -1, wl->low) == wl->low)
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
      mtev_atomic_cas32(&wl->cross, wl->low, -1);
      if (wl->cur <= wl->low) {
        /* possible that someone else has already started to enable. */
        if (mtev_atomic_cas32(&wl->cross, (mtev_atomic32_t) -1, wl->low) == wl->low)
          return MTEV_WATERLEVEL_TOGGLE_ENABLE;
      }
      break;
    case MTEV_WATERLEVEL_TOGGLE_ENABLE:
      /* same logic as above, but with high/low swapped. */
      mtev_atomic_cas32(&wl->cross, wl->high, -1);
      if (wl->cur >= wl->high) {
        if (mtev_atomic_cas32(&wl->cross, (mtev_atomic32_t) -1, wl->high) == wl->high)
          return MTEV_WATERLEVEL_TOGGLE_DISABLE;
      }
    default:
      break;
  }
  return MTEV_WATERLEVEL_TOGGLE_KEEP;
}
