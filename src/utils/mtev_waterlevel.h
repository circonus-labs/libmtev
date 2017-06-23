/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#ifndef MTEV_WATERLEVEL_H
#define MTEV_WATERLEVEL_H

typedef struct _mtev_waterlevel_t mtev_waterlevel_t;

typedef enum {
  MTEV_WATERLEVEL_TOGGLE_DISABLE=-1,
  MTEV_WATERLEVEL_TOGGLE_KEEP=0,
  MTEV_WATERLEVEL_TOGGLE_ENABLE=1,
} mtev_waterlevel_toggle_t;

mtev_waterlevel_t *mtev_waterlevel_create(int low, int high);
mtev_waterlevel_toggle_t mtev_waterlevel_adjust(mtev_waterlevel_t *wl, int by);
mtev_waterlevel_toggle_t mtev_waterlevel_ack(mtev_waterlevel_t *wl, mtev_waterlevel_toggle_t t);

#endif
