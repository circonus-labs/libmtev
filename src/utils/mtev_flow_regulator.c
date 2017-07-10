/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#include "mtev_flow_regulator.h"
#include "mtev_log.h"
#include <ck_pr.h>
#include <stdint.h>

#define MTEV_FLOW_REGULATOR_STATE_ENABLED 0
#define MTEV_FLOW_REGULATOR_STATE_DISABLING 1
#define MTEV_FLOW_REGULATOR_STATE_DISABLED 2
#define MTEV_FLOW_REGULATOR_STATE_ENABLING 3

struct _mtev_flow_regulator_t
{
  unsigned int cur;
  unsigned int state;
  unsigned int low;
  unsigned int high;
};

mtev_flow_regulator_t *mtev_flow_regulator_create(unsigned int low, unsigned int high)
{
  mtevAssert(low < high);
  mtev_flow_regulator_t *fr = calloc(1, sizeof(mtev_flow_regulator_t));
  fr->state = MTEV_FLOW_REGULATOR_STATE_ENABLED;
  fr->low = low;
  fr->high = high;
  return fr;
}

void mtev_flow_regulator_destroy(mtev_flow_regulator_t *fr)
{
  free((void *) fr);
}

static mtev_flow_regulator_toggle_t
mtev_flow_regulator_adjust_up(mtev_flow_regulator_t *fr, unsigned int adjustment)
{
  unsigned int old_val;

  do {
    old_val = ck_pr_load_uint(&fr->cur);
    if (old_val == fr->high) {
      if (ck_pr_cas_uint(&fr->state, MTEV_FLOW_REGULATOR_STATE_ENABLED,
                        MTEV_FLOW_REGULATOR_STATE_DISABLING))
        return MTEV_FLOW_REGULATOR_TOGGLE_DISABLE;
      else
        return MTEV_FLOW_REGULATOR_TOGGLE_DISABLED;
    }
  } while (ck_pr_cas_uint(&fr->cur, old_val, old_val+adjustment) == false);
  return MTEV_FLOW_REGULATOR_TOGGLE_KEEP;
}

mtev_flow_regulator_toggle_t mtev_flow_regulator_raise_one(mtev_flow_regulator_t *fr)
{
  return mtev_flow_regulator_adjust_up(fr, 1);
}

mtev_flow_regulator_toggle_t mtev_flow_regulator_lower(mtev_flow_regulator_t *fr, unsigned int by)
{
  unsigned int old_val;
  unsigned int new_val;

  do {
    old_val = ck_pr_load_uint(&fr->cur);
    mtevAssert(old_val >= by);
    new_val = old_val - by;
  } while (ck_pr_cas_uint(&fr->cur, old_val, new_val) == false);
  if (new_val <= fr->low) {
    if (ck_pr_cas_uint(&fr->state, MTEV_FLOW_REGULATOR_STATE_DISABLED,
                      MTEV_FLOW_REGULATOR_STATE_ENABLING))
      return MTEV_FLOW_REGULATOR_TOGGLE_ENABLE;
  }
  return MTEV_FLOW_REGULATOR_TOGGLE_KEEP;
}

mtev_flow_regulator_toggle_t
  mtev_flow_regulator_ack(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t)
{
  switch (t) {
    case MTEV_FLOW_REGULATOR_TOGGLE_DISABLE:
      mtevEvalAssert(ck_pr_cas_uint(&fr->state, MTEV_FLOW_REGULATOR_STATE_DISABLING,
                                   MTEV_FLOW_REGULATOR_STATE_DISABLED));
      return mtev_flow_regulator_lower(fr, 0);

    case MTEV_FLOW_REGULATOR_TOGGLE_ENABLE:
      mtevEvalAssert(ck_pr_cas_uint(&fr->state,
                                   MTEV_FLOW_REGULATOR_STATE_ENABLING,
                                   MTEV_FLOW_REGULATOR_STATE_ENABLED));
      return mtev_flow_regulator_adjust_up(fr, 0);
    default:
      break;
  }
  return MTEV_FLOW_REGULATOR_TOGGLE_KEEP;
}

mtev_boolean
mtev_flow_regulator_stable_try_raise_one(mtev_flow_regulator_t *fr) {
  mtev_flow_regulator_toggle_t t = mtev_flow_regulator_raise_one(fr);
  do {
    switch (t) {
    case MTEV_FLOW_REGULATOR_TOGGLE_DISABLED:
      /* no room to work, don't need to ACK. */
      return mtev_false;

    case MTEV_FLOW_REGULATOR_TOGGLE_DISABLE:
      /* no room to work for now, need to ACK, but maybe some more
       * room will be created as we process the ACK, so may need to
       * try again. */
      t = mtev_flow_regulator_ack(fr, t);
      /* only possible return values from `ack` above are `ENABLE` and
       * `KEEP`. If `ENABLE`, we'll need to loop through again. */
      if (t == MTEV_FLOW_REGULATOR_TOGGLE_KEEP) {
        /* still disabled, so return `mtev_false` early to prevent
         * client from trying to add data. */
        return mtev_false;
      }
      mtevAssert(t == MTEV_FLOW_REGULATOR_TOGGLE_ENABLE);
      break;

    case MTEV_FLOW_REGULATOR_TOGGLE_KEEP:
      /* successfully added a work item. when we exit the loop, we'll
       * return `mtev_true` at the bottom. */
      break;

    case MTEV_FLOW_REGULATOR_TOGGLE_ENABLE:
      /* Enough work drained while we were blocked trying to add this
       * work item that we may be able to do the work, now. */
      if ((t = mtev_flow_regulator_ack(fr, t)) ==
          MTEV_FLOW_REGULATOR_TOGGLE_KEEP) {
        /* successfully enabled, try to add the data agan. */
        t = mtev_flow_regulator_raise_one(fr);
      }
      break;
    }
  } while (t != MTEV_FLOW_REGULATOR_TOGGLE_KEEP);
  return mtev_true;
}

mtev_boolean mtev_flow_regulator_stable_lower(mtev_flow_regulator_t *fr,
                                              unsigned int by) {
  mtev_flow_regulator_toggle_t t = mtev_flow_regulator_lower(fr, by);
  mtev_flow_regulator_toggle_t last_t;
  do {
    last_t = t;
    t = mtev_flow_regulator_ack(fr, last_t);
  } while (t != MTEV_FLOW_REGULATOR_TOGGLE_KEEP);
  return last_t == MTEV_FLOW_REGULATOR_TOGGLE_ENABLE ? mtev_true : mtev_false;
}
