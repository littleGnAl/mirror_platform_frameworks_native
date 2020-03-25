/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <log/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include <sched.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 8956
#define MAX_LEN 256

#ifdef __cplusplus
extern "C"{
#include "control.h"
#include "dwm_hci_uwb.h"
//#include "function.h"
}
#endif

#include <private/android_filesystem_config.h>

#include "dwm_hci.h"

int sock = 0;
char buffer[MAX_LEN];
struct sockaddr_in serv_addr;

int n, len;

using namespace std;

namespace android {
// ---------------------------------------------------------------------------

#define DW1000_DEV_FILENAME             "/dev/dw1000"
#define SPI_INIT_COMMAND                "INIT"
#define INIT_COMMAND_TO_READ_DELAY      (3 * 1000  * 1000)
#define READ_TO_READ_DELAY              INIT_COMMAND_TO_READ_DELAY
#define READ_BYTES_REQUEST_SIZE         256

int32_t stripHCIbytes(char *c_buf, int32_t sz);
int32_t verifyJSONString(char *c_buf, int32_t sz);
int32_t getStrEndCharPos(char *c_buf, int32_t sz);

long long sock_send_count = 0;

void dwm_hci_uwb_cb(char *input_string)
{

    ALOGD("Socket send counter : %lld \n",sock_send_count++);
    ALOGD("App pointer : %p", input_string);
    ALOGD("From stack : %s", input_string);

    sendto(sock, reinterpret_cast<char *>(input_string), strlen(input_string), MSG_CONFIRM, reinterpret_cast<sockaddr *> (&serv_addr), sizeof(serv_addr));
    ALOGD("Message sent to app layer\n");	
		
}

int32_t dwm_hci_send_command_old(int32_t commandMask)
{
/*
    ALOGD("before checkCallingPermission\n");
    if (!checkCallingPermission(sLocationHardwarePermission, nullptr, nullptr)) {
        return PERMISSION_DENIED;
    }
*/
    int fd, sz;

    ALOGD("sending %d command to slave from master ...\n", commandMask);
    fd = open(DW1000_DEV_FILENAME, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
    {
        ALOGD("file open failed for %s Write mode\n", DW1000_DEV_FILENAME);
        return -1;
    }

    char *c_buf = reinterpret_cast<char *> (malloc(READ_BYTES_REQUEST_SIZE * 2 * sizeof(char)));
    if(c_buf == nullptr) {
        ALOGD("c_buf allocation failed, returning\n");
        return -1;
    }

    c_buf[0] = commandMask;
    c_buf[1] = '\0';

    ALOGD("calling write %s\n", c_buf);
    sz = write(fd, c_buf, strlen(c_buf));

    ALOGD("fd = %d, strlen(cmd.c_str()) = %zu, It returned %d\n", fd, strlen(c_buf), sz);

    close(fd);
    ALOGD("close done for write, returning");

    return sz;
}

int32_t dwm_hci_send_command(int32_t commandMask)
{

    static int init_range = 0;
    cb_register(&dwm_hci_uwb_cb);

    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
	ALOGD("Socket creation failed\n");
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    ALOGD("Commented lib calls/sending %d command to slave from master ...\n", commandMask);

//    const char *init = "init";

//    sendto(sock, reinterpret_cast<char *>(init), strlen(init), MSG_CONFIRM, reinterpret_cast<sockaddr *> (&serv_addr), sizeof(serv_addr));
    ALOGD("Init OK");	

    if(commandMask == 2)
    {   
	ALOGD("DWIA - DWM-HCI Calling Final Stop Ranging\n");
        stop_ranging(NULL);
	init_range = 0;	
	return 0;
    }

    if(commandMask == 0 || commandMask == 1)
    {   
        //if(init_range == 0)
	{
        	init_ranging(commandMask);	
       		ALOGD("DWIA - HCI Calling Final Init Ranging\n");
		init_range = 1;
	}
	ALOGD("DWIA - HCI Init done. Starting ranging %d", commandMask);
	start_ranging(commandMask);
    }
    
    ALOGD("DWIA - Return after start-ranging\n");  
    
    return 0;
}


String8 dwm_hci_read_data() {
/*
    ALOGD("before checkCallingPermission\n");
    if (!checkCallingPermission(sLocationHardwarePermission, nullptr, nullptr)) {
        String8 retValNull  = String8("");
        return retValNull;
    }
*/
    int fd, sz;
    //return String8("{\"rng\":1.2");
    char *c_buf = reinterpret_cast<char *> (malloc(READ_BYTES_REQUEST_SIZE * 2 * sizeof(char)));
    if(c_buf == nullptr) {
        ALOGD("c_buf allocation failed, returning\n");
        return String8("");
    }

    ALOGD("before open of device file, O_RDWR mode");
    fd = open(DW1000_DEV_FILENAME, O_RDWR);
    if (fd < 0)
    {
        ALOGD("file open failed for %s Read mode\n", DW1000_DEV_FILENAME);
        return String8("");
    }

    ALOGD("File open for RW done, fd=%d\n", fd);
    ALOGD("Those bytes are as follows: \n");
    sz = 0;
    while(sz == 0) {
        ALOGD("calling write before read\n");
        c_buf[0] = DW_HCI_START; // dummy command
        c_buf[1] = '\0';

        sz = write(fd, c_buf, READ_BYTES_REQUEST_SIZE);
        ALOGD("after dummy command write sz=%d", sz);

        sz = read(fd, c_buf, READ_BYTES_REQUEST_SIZE);
        c_buf[sz] = '\0';
        ALOGD("after read sz=%d, %s", sz, c_buf);

        int32_t retVal = stripHCIbytes(c_buf, sz);
        if(-1 == retVal) {
            ALOGD("stripHCIbytes returned -1\n");
            return String8("");
        }
    }

    ALOGD("returning\n");
    String8 retVal  = String8(c_buf);

    close(fd);
    free(c_buf);

    return retVal;
}

int32_t verifyJSONString(char *c_buf, int32_t sz) {
    ALOGD("entered verifyJSONString c_buf=%s sz=%d\n", c_buf, sz);
    return 1;
}

int32_t getStrEndCharPos(char *c_buf, int32_t sz) {
    int32_t i = 0;

    for(i = 0; i < sz; i++) {
        if('\0' == c_buf[i]) {
            return i;
        }
    }

    return -1;
}

int32_t stripHCIbytes(char *c_buf, int32_t sz) {

    int32_t i = 0;
    int32_t strEndPos = getStrEndCharPos(c_buf, sz);
    if(-1 == strEndPos) {
        return -1;
    }

    for(i = 2; i <= strEndPos; i++) {
        c_buf[i - 2] = c_buf[i];
    }

    return 0;
}

}; // namespace android
