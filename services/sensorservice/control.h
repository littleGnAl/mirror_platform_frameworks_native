#ifndef _CONTROL_H_
#define _CONTROL_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <float.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#define TWR_SS_TAG     "/sys/kernel/uwbcore/uwbrng/twr_ss"
#define TWR_SS_ACK_TAG "/sys/kernel/uwbcore/uwbrng/twr_ss_ack"
#define TWR_SS_EXT_TAG "/sys/kernel/uwbcore/uwbrng/twr_ss_ext"
#define TWR_DS_TAG     "/sys/kernel/uwbcore/uwbrng/twr_ds"
#define TWR_DS_EXT_TAG "/sys/kernel/uwbcore/uwbrng/twr_ds_ext"
#define TWR_NODE       "/sys/kernel/uwbcore/uwbrng/listen"
#define RANGE_GET      "/dev/uwbrng"
#define PDOA_MODE      "/sys/kernel/uwbcore/uwbcfg/rx_pdoa_mode"
#define STS_MODE       "/sys/kernel/uwbcore/uwbcfg/rx_sts_mode"
#define PREAM_LEN      "/sys/kernel/uwbcore/uwbcfg/tx_pream_len"
#define STS_LEN        "/sys/kernel/uwbcore/uwbcfg/rx_sts_len"

typedef void (*dwm_cb_fn_ptr)(char* input_string);
struct dwm_cb {
    dwm_cb_fn_ptr call_back;
};

#define CLI_ADDR       "/sys/kernel/uwbcore/dw3000_cli/addr"
#define FRAME_FILTER   "/sys/kernel/uwbcore/uwbcfg/frame_filter"
#define COMMIT         "/sys/kernel/uwbcore/uwbcfg/commit"

#define RANGE_LEN      256

#define CLK_TCK 1000000

struct uwb_range
{
    void (*complete_cb)(void *);
    char *role;
};

struct rng_arg
{
    int s_fd;
    char *buff;

};


void  init_ranging(int arg);
void * stop_ranging(void *arg);
void * start(void *arg);
void  start_ranging(int arg);
void *cb_register(dwm_cb_fn_ptr cb);

#ifdef __cplusplus
}
#endif
#endif
