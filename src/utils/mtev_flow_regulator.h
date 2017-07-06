/*
 * Copyright (c) 2017, Circonus, Inc.
 * All rights reserved.
 */
#ifndef MTEV_FLOW_REGULATOR_H
#define MTEV_FLOW_REGULATOR_H

/*! \file mtev_flow_regulator.h

    Throughput limiter for event-driven processes. Libmtev encourages
    an application architecture that generates work items via the
    event-loop, and moving those work items to processors via queues.
    Unless care is taken, this can result in very large queue depths
    if the event-loop generates work faster than the processing
    threads can handle it, and can reduce the opportunity for
    back-pressure to be applied to the work-generator. (For example,
    if the work is derived from TCP socket data, then reading data
    from the socket as soon as possible empties the TCP window,
    allowing the remote end of the connection to continue feeding data
    in, at a rate decoupled from the receiver's ability to perform the
    required work.) `mtev_flow_regulator` provides a mechanism for
    limiting work-queue depth, reducing memory strain and other forms
    of resource contention, and (sometimes) applying back-pressure to
    work generators.

    A flow-regulator is either enabled (meaning that new work can be
    added) or disabled, with transitions between the states signalled
    to clients when work is either added
    (`mtev_flow_regulator_raise_one`) or removed
    (`mtev_flow_regulator_lower`). It's then up to the client to
    respond to this signal, starting or stopping the stream of work.
    After modifying the work stream, the client informs the
    flow-regulator of the change, by calling
    `mtev_flow_regulator_ack`. `mtev_flow_regulator_ack` is
    complicated by the fact that the queue depth can change while the
    client is manipulating the work-flow, such that the flow needs to
    be switched _again_. As such, the client _may_ have to call
    `mtev_flow_regulator_ack` in a loop, until it returns that the
    flow has stabilized. For cases where no explicit action has to be
    taken between raising / lowering the work level and acknowledging
    the current flow state, `mtev_flow_regulator_stabilize` can be
    used to simplify the looping logic.
*/

typedef struct _mtev_flow_regulator_t mtev_flow_regulator_t;

typedef enum {
  MTEV_FLOW_REGULATOR_TOGGLE_DISABLED=-2,
  MTEV_FLOW_REGULATOR_TOGGLE_DISABLE=-1,
  MTEV_FLOW_REGULATOR_TOGGLE_KEEP=0,
  MTEV_FLOW_REGULATOR_TOGGLE_ENABLE=1,
} mtev_flow_regulator_toggle_t;

/*! \fn mtev_flow_regulator_t *mtev_flow_regulator_create(unsigned int low, unsigned int high)
    \brief Create a flow-regulator object.
    \param low Threshold that indicates when work flow should be re-enabled.
    \param high Threshold at which to stop work flow. Must be strictly greater than `low`.
    \return Flow-regulator object.

    The returned flow-regulator object is "enabled" on creation. When
    `high` work items are added (by `mtev_flow_regulator_raise_one`)
    without being removed (by `mtev_flow_regulator_lower`), the
    flow-regulator will become disabled. When `high - low` work-items
    are subsequently marked done (by `mtev_flow_regulator_lower`),
    without new work being added (by `mtev_flow_regulator_raise_one`),
    the flow-regulator will transition back to "enabled".
 */
mtev_flow_regulator_t *mtev_flow_regulator_create(unsigned int low, unsigned int high);
/*! \fn void mtev_flow_regulator_destroy(mtev_flow_regulator_t *fr)
    \brief Destroy a flow-regulator object.
 */
void mtev_flow_regulator_destroy(mtev_flow_regulator_t *fr);
/*! \fn mtev_flow_regulator_toggle_t mtev_flow_regulator_raise_one(mtev_flow_regulator_t *fr)
    \brief Reserve space for a work-item in a flow-regulator.
    \return Success / fail status on inserting work.

    See `mtev_flow_regulator_ack` for description of how to handle the
    return value. This function will return one of:

    * `MTEV_FLOW_REGULATOR_TOGGLE_DISABLED`
    * `MTEV_FLOW_REGULATOR_TOGGLE_DISABLE`
    * `MTEV_FLOW_REGULATOR_TOGGLE_KEEP`

    Note that, unless the return value was
    `MTEV_FLOW_REGULATOR_TOGGLE_KEEP`, space was _not_ reserved in the
    flow-regulator for the work-item.
 */
mtev_flow_regulator_toggle_t mtev_flow_regulator_raise_one(mtev_flow_regulator_t *fr);
/*! \fn mtev_flow_regulator_toggle_t mtev_flow_regulator_lower(mtev_flow_regulator_t *fr, unsigned int by)
    \brief Release space for work-items in a flow-regulator.
    \param by Number of work-items to mark completed.
    \return Action to take on releasing work.

    See `mtev_flow_regulator_ack` for description of how to handle the
    return value. This function will return one of:

  * `MTEV_FLOW_REGULATOR_TOGGLE_KEEP`
  * `MTEV_FLOW_REGULATOR_TOGGLE_ENABLE`
 */
mtev_flow_regulator_toggle_t mtev_flow_regulator_lower(mtev_flow_regulator_t *fr, unsigned int by);
/*! \fn mtev_flow_regulator_toggle_t mtev_flow_regulator_ack(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t)
    \brief Acknowledge processing mtev_flow_regulator_toggle_t instruction.
    \param t Instruction returned from previous call to `mtev_flow_regulator_raise_one`, `mtev_flow_regulator_lower`, or `mtev_flow_regulator_ack`.
    \return New flow-toggle instruction.

    The flow-regulator is designed to be usable in multi-producer
    (where multiple concurrent entities may produce work) /
    multi-consumer (where multiple concurrent entities may mark work
    completed) scenarios, which means that many entities may be adding
    and removing work from the flow-regulator at the same time. As
    such, when one entity observes that the flow-regulator has become
    disabled and takes some action to pause further work generation,
    it's possible that enough work will have drained from the
    flow-regulator that it needs to be re-enabled... Or, that after
    re-enabling the flow-regulator, enough work was already being
    scheduled that it needs to be disabled again. So
    `mtev_flow_regulator_ack` returns a _new_ instruction, in case the
    flow-regulator needs further adjustment. Clients are expected to
    call this function in a loop, with the function's previous return
    value, until the flow-regulator settles on
    `MTEV_FLOW_REGULATOR_TOGGLE_KEEP` or
    `MTEV_FLOW_REGULATOR_TOGGLE_DISABLED`. (There is no harm in
    continuing to call `mtev_flow_regulator_ack` after it reaches one
    of these values: it will eventually settle on
    `MTEV_FLOW_REGULATOR_TOGGLE_KEEP`.)

    The toggle-instruction should be interpreted as follows:

    * `MTEV_FLOW_REGULATOR_TOGGLE_DISABLED`: Flow control is currently
      disabled. No client action necessary.
    * `MTEV_FLOW_REGULATOR_TOGGLE_DISABLE`: Flow control _was_ enabled,
      and we've started transitioning to DISABLED. (The transition to
      DISABLED is not complete until the client calls
      `mtev_flow_regulator_ack`, again.) Client MAY try to prevent
      generating new work before calling `mtev_flow_regulator_ack`, again.
    * `MTEV_FLOW_REGULATOR_TOGGLE_KEEP`: No client action required.
    * `MTEV_FLOW_REGULATOR_TOGGLE_ENABLE`: Flow control _was_ disabled,
      and has just started transitioning to ENABLED. (The transition to
      ENABLED is not complete until the client calls
      `mtev_flow_regulator_ack`, again.) Client MAY re-enable
      work-generation before calling `mtev_flow_regulator_ack`, again.


    To facilitate multi-producer / multi-consumer use, the
    flow-regulator enforces that only _one_ client will see a
    flow-toggling result (_i.e._ `MTEV_FLOW_REGULATOR_TOGGLE_ENABLE`
    or `MTEV_FLOW_REGULATOR_TOGGLE_DISABLE`) until that client calls
    `mtev_flow_regulator_ack`, and that the same toggling result will
    not occur twice in a row across all concurrent clients.
 */
mtev_flow_regulator_toggle_t
  mtev_flow_regulator_ack(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t);
/*! \fn mtev_flow_regulator_toggle_t mtev_flow_regulator_stabilize(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t)
    \param t Instruction returned from previous call to `mtev_flow_regulator_raise_one`, `mtev_flow_regulator_lower`, or `mtev_flow_regulator_ack`.
    \return New flow-toggle instruction.

    This function is a simple wrapper around
    `mtev_flow_regulator_ack`, to simplify handling in cases where the
    client needs take no explicit action to enable or disable
    work-production before calling `mtev_flow_regulator_ack`. It
    simply calls `mtev_flow_regulator_ack` in a loop until
    `mtev_flow_regulator_ack` returns
    `MTEV_FLOW_REGULATOR_TOGGLE_KEEP`, and returns the previous toggle
    instruction, which the client would then use to enable or disable
    work-generation.
 */
mtev_flow_regulator_toggle_t
  mtev_flow_regulator_stabilize(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t);

#endif
