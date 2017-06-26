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
  int cur;
  int state;
  int low;
  int high;
};

mtev_flow_regulator_t *mtev_flow_regulator_create(int low, int high)
{
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
  int signed_adjustment = (int) adjustment;
  int old_val;

  do {
    old_val = ck_pr_load_int(&fr->cur);
    if (old_val == fr->high) {
      if (ck_pr_cas_int(&fr->state, MTEV_FLOW_REGULATOR_STATE_ENABLED,
                        MTEV_FLOW_REGULATOR_STATE_DISABLING))
        return MTEV_FLOW_REGULATOR_TOGGLE_DISABLE;
      else
        return MTEV_FLOW_REGULATOR_TOGGLE_DISABLED;
    }
  } while (ck_pr_cas_int(&fr->cur, old_val, old_val+signed_adjustment) == false);
  return MTEV_FLOW_REGULATOR_TOGGLE_KEEP;
}

mtev_flow_regulator_toggle_t mtev_flow_regulator_raise_one(mtev_flow_regulator_t *fr)
{
  return mtev_flow_regulator_adjust_up(fr, 1);
}

mtev_flow_regulator_toggle_t mtev_flow_regulator_lower(mtev_flow_regulator_t *fr, unsigned int by)
{
  int signed_adjustment = -1 * ((int) by);
  int old_val;
  int new_val;

  do {
    old_val = ck_pr_load_int(&fr->cur);
    new_val = old_val+signed_adjustment;
  } while (ck_pr_cas_int(&fr->cur, old_val, new_val) == false);
  if (new_val < fr->low) {
    if (ck_pr_cas_int(&fr->state, MTEV_FLOW_REGULATOR_STATE_DISABLED,
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
      mtevEvalAssert(ck_pr_cas_int(&fr->state, MTEV_FLOW_REGULATOR_STATE_DISABLING,
                                   MTEV_FLOW_REGULATOR_STATE_DISABLED));
      return mtev_flow_regulator_lower(fr, 0);

    case MTEV_FLOW_REGULATOR_TOGGLE_ENABLE:
      mtevEvalAssert(ck_pr_cas_int(&fr->state,
                                   MTEV_FLOW_REGULATOR_STATE_ENABLING,
                                   MTEV_FLOW_REGULATOR_STATE_ENABLED));
      return mtev_flow_regulator_adjust_up(fr, 0);
    default:
      break;
  }
  return MTEV_FLOW_REGULATOR_TOGGLE_KEEP;
}

mtev_flow_regulator_toggle_t
  mtev_flow_regulator_stabilize(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t)
{
  mtev_flow_regulator_toggle_t last_t;
  do {
    last_t = t;
    t = mtev_flow_regulator_ack(fr, last_t);
  } while (t != MTEV_FLOW_REGULATOR_TOGGLE_KEEP);
  return last_t;
}
