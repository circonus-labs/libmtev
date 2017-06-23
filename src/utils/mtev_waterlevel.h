/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#ifndef MTEV_WATERLEVEL_H
#define MTEV_WATERLEVEL_H

/* mtev_waterlevel - manage 
 */

typedef struct _mtev_waterlevel_t mtev_waterlevel_t;

typedef enum {
  MTEV_WATERLEVEL_TOGGLE_DISABLED=-2,
  MTEV_WATERLEVEL_TOGGLE_DISABLE=-1,
  MTEV_WATERLEVEL_TOGGLE_KEEP=0,
  MTEV_WATERLEVEL_TOGGLE_ENABLE=1,
} mtev_waterlevel_toggle_t;

mtev_waterlevel_t *mtev_waterlevel_create(int low, int high);
mtev_waterlevel_toggle_t mtev_waterlevel_raise_one(mtev_waterlevel_t *wl);
mtev_waterlevel_toggle_t mtev_waterlevel_lower(mtev_waterlevel_t *wl, unsigned int by);
mtev_waterlevel_toggle_t mtev_waterlevel_ack(mtev_waterlevel_t *wl, mtev_waterlevel_toggle_t t);

#endif
