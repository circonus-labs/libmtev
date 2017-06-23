/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#ifndef MTEV_FLOW_REGULATOR_H
#define MTEV_FLOW_REGULATOR_H

/* mtev_flow_regulator - manage 
 */

typedef struct _mtev_flow_regulator_t mtev_flow_regulator_t;

typedef enum {
  MTEV_FLOW_REGULATOR_TOGGLE_DISABLED=-2,
  MTEV_FLOW_REGULATOR_TOGGLE_DISABLE=-1,
  MTEV_FLOW_REGULATOR_TOGGLE_KEEP=0,
  MTEV_FLOW_REGULATOR_TOGGLE_ENABLE=1,
} mtev_flow_regulator_toggle_t;

mtev_flow_regulator_t *mtev_flow_regulator_create(int low, int high);
void mtev_flow_regulator_destroy(mtev_flow_regulator_t *fr);
mtev_flow_regulator_toggle_t mtev_flow_regulator_raise_one(mtev_flow_regulator_t *fr);
mtev_flow_regulator_toggle_t mtev_flow_regulator_lower(mtev_flow_regulator_t *fr, unsigned int by);
mtev_flow_regulator_toggle_t
  mtev_flow_regulator_ack(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t);

#endif
