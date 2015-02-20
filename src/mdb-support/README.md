Looking at logs:

    ::mtev_log | ::print struct _mtev_log_stream
    ::mtev_log | ::mtev_print_membuf_log
    ::mtev_log internal | ::mtev_print_membuf_log

Looking at events using `::print_event`

    > 0x10451f8e0 ::print_event
    0x10451f8e0 = {
        callback = mtev_listener_acceptor
        closure  = 0x104a42100
        fd       = 43 (67t)
        opset    = snowthd`_eventer_POSIX_fd_opset (0)
        mask     = READ,EXCEPTION
    }

Looking at timed events:

    *timed_events ::walk mtev_skiplist | ::print struct _event
    ::eventer_timed | ::print_event

Looking at file descriptor events:

    ::walk eventer_fds | ::print struct _event
    ::eventer_fd | ::print_event

    ::eventer_fd 43 | ::print_event

Looking at eventer jobqs:

    all_queues ::walk mtev_hash | ::print eventer_jobq_t queue_name
    ::eventer_jobq | ::print eventer_jobq_t queue_name

    ::eventer_jobq default_back_queue | ::print eventer_jobq_t
