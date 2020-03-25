//#include <os/os_dev.h>
// #include "os/mynewt.h"
#include <utils/String8.h>

namespace android {
/*
  1 byte command
  0 t0 6 bits represent command.
  7th bit represents whether it is a response message.
*/
#define DW_HCI_START                  0
#define DW_HCI_STOP                   1
#define DW_HCI_GET_DATA               2

#define DW_HCI_TASK_MASK              (4)
#define DW_HCI_START_MASK             (DW_HCI_START << DW_HCI_TASK_MASK)
#define DW_HCI_STOP_MASK              (DW_HCI_STOP << DW_HCI_TASK_MASK)
#define DW_HCI_GET_DATA_MASK          (DW_HCI_GET_DATA << DW_HCI_TASK_MASK)

#define DW_HCI_TDMA                   1
#define DW_HCI_TDMA_START             (DW_HCI_TDMA | DW_HCI_START_MASK )
#define DW_HCI_TDMA_STOP              (DW_HCI_TDMA | DW_HCI_STOP_MASK )
#define DW_HCI_TDMA_GET_DATA          (DW_HCI_TDMA | DW_HCI_GET_DATA_MASK )

#define DW_HCI_TWR_SS                 2
#define DW_HCI_TWR_SS_START           (DW_HCI_TWR_SS | DW_HCI_START_MASK )
#define DW_HCI_TWR_SS_STOP            (DW_HCI_TWR_SS | DW_HCI_STOP_MASK )
#define DW_HCI_TWR_SS_GET_DATA        (DW_HCI_TWR_SS | DW_HCI_GET_DATA_MASK )

#define DW_HCI_TWR_DS                 3
#define DW_HCI_TWR_DS_START           (DW_HCI_TWR_DS | DW_HCI_START_MASK )
#define DW_HCI_TWR_DS_STOP            (DW_HCI_TWR_DS | DW_HCI_STOP_MASK )
#define DW_HCI_TWR_DS_GET_DATA        (DW_HCI_TWR_DS | DW_HCI_GET_DATA_MASK )

#define DW_HCI_NRNG_SS                4
#define DW_HCI_NRNG_SS_START          (DW_HCI_NRNG_SS | DW_HCI_START_MASK )
#define DW_HCI_NRNG_SS_STOP           (DW_HCI_NRNG_SS | DW_HCI_STOP_MASK )
#define DW_HCI_NRNG_SS_GET_DATA       (DW_HCI_NRNG_SS | DW_HCI_GET_DATA_MASK )

#define DW_HCI_NTDOA                  5
#define DW_HCI_NTDOA_START            (DW_HCI_NTDOA | DW_HCI_START_MASK )
#define DW_HCI_NTDOA_STOP             (DW_HCI_NTDOA | DW_HCI_STOP_MASK )
#define DW_HCI_NTDOA_GET_DATA         (DW_HCI_NTDOA | DW_HCI_GET_DATA_MASK )

#define DW_HCI_PDOA                   6
#define DW_HCI_PDOA_START             (DW_HCI_PDOA | DW_HCI_START_MASK )
#define DW_HCI_PDOA_STOP              (DW_HCI_PDOA | DW_HCI_STOP_MASK )
#define DW_HCI_PDOA_GET_DATA          (DW_HCI_PDOA | DW_HCI_GET_DATA_MASK )

#define DW_HCI_EDM                    7
#define DW_HCI_EDM_START              (DW_HCI_EDM | DW_HCI_START_MASK )
#define DW_HCI_EDM_STOP               (DW_HCI_EDM | DW_HCI_STOP_MASK )
#define DW_HCI_EDM_GET_DATA           (DW_HCI_EDM | DW_HCI_GET_DATA_MASK )

#define DW_HCI_UWBCFG                 8
#define DW_HCI_UWBCFG_SET_PARAMS      (DW_HCI_EDM | DW_HCI_START_MASK )
#define DW_HCI_UWBCFG_GET_PARAMS      (DW_HCI_EDM | DW_HCI_GET_DATA_MASK )

#define DW_HCI_RESP                   (1<<7)
#define DW_HCI_MAX_COMMANDS           DW_HCI_UWBCFG
#define DW_HCI_MAX_TASKS              DW_HCI_GET_DATA

//#define DW_API_INIT_RANGING			  1
#define DW_ROLE_TAG			  0
#define DW_ROLE_NODE			  1	
#define DW_STOP_RNG 			  2


int32_t dwm_hci_send_command(int32_t commandMask);

String8 dwm_hci_read_data();

}; // namespace android
