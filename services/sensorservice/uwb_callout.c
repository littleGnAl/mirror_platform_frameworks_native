#include "control.h"
#include "uwb_callout.h"

uint32_t
uwb_time_get(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) {
        return 0;
    }
    /* Handle 32bit overflow */
    uint64_t v = now.tv_sec * 1000000 + now.tv_nsec / 1000;
    while (v > 0xffffffffUL) v -= 0xffffffffUL;
    return (uint32_t)v;
}

void 
uwb_callout_init(struct uwb_callout *uc, uwb_event_fn range_cb , struct rng_arg *arg)
{   
    struct sigevent event;

    /* Initialize the callout. */
    uc->uc_active = false;

    event.sigev_notify = SIGEV_THREAD;
    event.sigev_value.sival_ptr = arg;  
    event.sigev_notify_function = range_cb;
    event.sigev_notify_attributes = NULL;

    timer_create(CLOCK_REALTIME, &event, &uc->uc_timer);
}


int 
uwb_callout_reset(struct uwb_callout *uc,
        uint32_t ticks)
{
    struct itimerspec its;

    if (ticks < 0) {
        return -1;
    }

    if (ticks == 0) {
        ticks = 1;
    }

    uc->uc_ticks = uwb_time_get() + ticks;

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;                     // one shot
    its.it_value.tv_sec = (ticks / 1000000);
    its.it_value.tv_nsec = (ticks % 1000000) * 1000; // expiration
    its.it_value.tv_nsec %= 1000000000;
    uc->uc_active = true;
    timer_settime(uc->uc_timer, 0, &its, NULL);

    return 0;
}


int uwb_callout_inited(struct uwb_callout *uc)
{
    return (uc->uc_timer != NULL);
}



void uwb_callout_stop(struct uwb_callout *uc)
{
    if (!uwb_callout_inited(uc)) {
        return;
    }
    struct itimerspec its;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = 0;
    timer_settime(uc->uc_timer, 0, &its, NULL);
    uc->uc_active = false;
}

