/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#ifndef MTEV_FLOW_REGULATOR_H
#define MTEV_FLOW_REGULATOR_H

/* mtev_flow_regulator - Throughput limiter for event-driven processes.
 *
 * Libmtev encourages an application architecture that generates work
 * items via the event-loop, and moving those work items to processors
 * via queues. Unless care is taken, this can result in very large
 * queue depths if the event-loop generates work faster than the
 * processing threads can handle it, and can reduce the opportunity
 * for back-pressure to be applied to the work-generator. (For
 * example, if the work is derived from TCP socket data, then reading
 * data from the socket as soon as possible empties the TCP window,
 * allowing the remote end of the connection to continue feeding data
 * in, at a rate decoupled from the receiver's ability to perform the
 * required work.) mtev_flow_regulator provides a mechanism for
 * limiting work-queue depth, reducing memory strain and other forms
 * of resource contention, and (sometimes) applying back-pressure to
 * work generators.
 *
 * A flow-regulator is either enabled (meaning that new work can be
 * added) or disabled, with transitions between the states signalled
 * to clients when work is either added
 * (mtev_flow_regulator_raise_one) or removed
 * (mtev_flow_regulator_lower). It's then up to the client to respond
 * to this signal, starting or stopping the stream of work. After
 * modifying the work stream, the client informs the flow-regulator of
 * the change, by calling mtev_flow_regulator_ack.
 * mtev_flow_regulator_ack is complicated by the fact that the queue
 * depth can change while the client is manipulating the work-flow,
 * such that the flow needs to be switched _again_. As such, the
 * client _may_ have to call mtev_flow_regulator_ack in a loop, until
 * it returns that the flow has stabilized. For cases where no
 * explicit action has to be taken between raising / lowering the work
 * level and acknowledging the current flow state,
 * mtev_flow_regulator_stabilize can be used to simplify the looping
 * logic.
 */

typedef struct _mtev_flow_regulator_t mtev_flow_regulator_t;

typedef enum {
  MTEV_FLOW_REGULATOR_TOGGLE_DISABLED=-2,
  MTEV_FLOW_REGULATOR_TOGGLE_DISABLE=-1,
  MTEV_FLOW_REGULATOR_TOGGLE_KEEP=0,
  MTEV_FLOW_REGULATOR_TOGGLE_ENABLE=1,
} mtev_flow_regulator_toggle_t;

mtev_flow_regulator_t *mtev_flow_regulator_create(unsigned int low, unsigned int high);
void mtev_flow_regulator_destroy(mtev_flow_regulator_t *fr);
mtev_flow_regulator_toggle_t mtev_flow_regulator_raise_one(mtev_flow_regulator_t *fr);
mtev_flow_regulator_toggle_t mtev_flow_regulator_lower(mtev_flow_regulator_t *fr, unsigned int by);
mtev_flow_regulator_toggle_t
  mtev_flow_regulator_ack(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t);
mtev_flow_regulator_toggle_t
  mtev_flow_regulator_stabilize(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t);

#endif
