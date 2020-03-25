#ifndef _UWB_CALLOUT_H_
#define _UWB_CALLOUT_H_

#include <time.h>

struct uwb_callout
{
    uint32_t uc_ticks;
    timer_t  uc_timer;
    bool     uc_active;
};

typedef void (*uwb_event_fn)(union sigval );
int uwb_callout_reset(struct uwb_callout *c,uint32_t ticks);
uint32_t uwb_time_get(void);
void uwb_callout_init(struct uwb_callout *uc, uwb_event_fn range_cb , struct rng_arg *arg);
int uwb_callout_reset(struct uwb_callout *uc,uint32_t ticks);
int uwb_callout_inited(struct uwb_callout *uc);
void uwb_callout_stop(struct uwb_callout *uc);

#endif
