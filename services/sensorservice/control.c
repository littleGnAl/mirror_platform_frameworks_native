#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "control.h"
#include "uwb_callout.h"
#include <semaphore.h>
#include <pthread.h>
#include <time.h>
#include <android/log.h>
#define TAG "control"

#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)

pthread_t g_range,s_range;
static struct uwb_callout range_callout;
int s_fd=-1,g_fd=-1;
int RANGE=0;

struct dwm_cb g_dwm_cb = {NULL} ;
char json_string[256];

void * cb_register(dwm_cb_fn_ptr cb)
{
	g_dwm_cb.call_back = cb;
	return NULL;
}

static void 
uwb_range_cb(union sigval sv)
{   
    int ret;
    struct rng_arg *ev= (struct rng_arg *)sv.sival_ptr;
    if(ev->buff){
        ret=write(ev->s_fd, ev->buff, strlen(ev->buff));
        if(ret==-1) {
            perror("DWIA write:");
        }
    }
    uwb_callout_reset(&range_callout,CLK_TCK/200);
}

int
config_write(char *path, char *val)
{
    int fd=-1,ret=0;
    

    fd = open(path, O_WRONLY|O_CREAT, (S_IRWXU | S_IRWXG | S_IRWXO));
    if (fd < 0) {
        LOGD("CONTROL_UWB Config_write : Failed to open file");
        return -1;
    }
    ret=write(fd, val, strlen(val));
    if(ret==-1) {
        LOGD("CONTROL_UWB Config_write : Write Error");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

void  
init_ranging(int arg)
{

    char *path="";
	LOGD("Entered init ranging\n");
    if(arg==1)
    {
        path=TWR_NODE;
        config_write(CLI_ADDR,"0x1234"); //Node -own add 
        config_write(FRAME_FILTER,"0xF");
    }
    else
    {
        path=TWR_SS_ACK_TAG;
        config_write(FRAME_FILTER,"0");
    }
   
   config_write(PREAM_LEN,"64");
   config_write(STS_LEN,"256"); 
   config_write(PDOA_MODE, "3");
   config_write(STS_MODE, "1sdc");
   config_write(COMMIT,"1");

    s_fd = open(path, O_WRONLY | O_CREAT, (S_IRWXU | S_IRWXG | S_IRWXO));
    if (s_fd < 0) {
		if(errno==ENOENT)
			LOGD("DWIA: SYSFS file doesn't exist. ");
		else
			LOGD("DWIA: Failed to open the sysfs file...");
    }

    g_fd = open(RANGE_GET, O_RDONLY | O_CREAT, (S_IRWXU | S_IRWXG | S_IRWXO));
    if (g_fd < 0) {
		if(errno==ENOENT)
			LOGD("DWIA: Device file doesn't exist.");
		else
			LOGD("DWIA: Failed to open the device file...");
    }
    LOGD("CONTROL_UWB: path: %s, arg: %d, DWIA: init s_fd: %d, g_fd: %d\n",path,arg,s_fd,g_fd);
}

void * 
stop_ranging(void *arg)
{
    RANGE=0; 
    LOGD("CONTROL_UWB: DWIA: Stop Ranging called in %s\n", __FILE__);    
    LOGD("CONTROL_UWB: DWIA: Stop s_fd: %d, g_fd: %d\n",s_fd,g_fd);
    LOGD("CONTROL_UWB: DWIA: Stop s_range: %ld, g_range: %ld\n",(long)s_range,(long)g_range);
    
    uwb_callout_stop(&range_callout);  
    if(close(s_fd)==-1)
    {
        LOGD("DWIA: Failed to close the sysfs file...");
    }
    if(close(g_fd)==-1)
    {
        LOGD("DWIA: Failed to close the device file...");
    }

    return arg;
}


void * 
start(void * arg)
{
    char *buff;
    struct rng_arg fn_arg;
    if(*(int *)arg==1)
    {
        buff="0"; //time out 
    }
    else
    {
        buff="0x1234"; //dest add
    }
    fn_arg.s_fd=s_fd;
    fn_arg.buff=buff;

    uwb_callout_init(&range_callout,uwb_range_cb, &fn_arg);

    uwb_callout_reset(&range_callout,CLK_TCK/60);
    while(RANGE);
    return arg;
}

void *
get(void *arg)
{
    int ret=0;

    while(RANGE){
        ret=read(g_fd, json_string, RANGE_LEN);

        if(ret==-1) {
            LOGD("DWIA read:");
        }
		LOGD("DWIA: %s", json_string);
		
		if(g_dwm_cb.call_back != NULL) {
			g_dwm_cb.call_back(json_string);
		}
    }
    pthread_exit(NULL);
    return arg;
}

void  
start_ranging(int arg)
{
	LOGD("DWIA: Entered start ranging\n");
    RANGE=1;
    pthread_create(&s_range, NULL, start,&arg);
    pthread_create(&g_range, NULL, get, NULL);
    LOGD("CONTROL_UWB: DWIA: start: s_range: %ld, g_range: %ld\n",(long)s_range,(long)g_range);
}
