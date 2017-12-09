#include <sched.h>
#include <unistd.h>

#include <log/log.h>
#include <sys/resource.h>

#include <pdx/service_dispatcher.h>

#include "buffer_hub.h"

int main(int, char**) {
  int ret = -1;
  std::shared_ptr<android::pdx::Service> service;
  std::unique_ptr<android::pdx::ServiceDispatcher> dispatcher;
  struct sched_param param = {0};

  const int fifo_min = sched_get_priority_min(SCHED_FIFO);
  const int fifo_max = sched_get_priority_max(SCHED_FIFO);
  const int fifo_range = fifo_max - fifo_min;
  const int fifo_medium = fifo_min + fifo_range / 5;

  // We need to be able to create endpoints with full perms.
  umask(0000);

  // Bump up the soft limit of open fd to the hard limit.
  struct rlimit64 rlim;
  ret = getrlimit64(RLIMIT_NOFILE, &rlim);
  LOG_ALWAYS_FATAL_IF(ret != 0, "Failed to get nofile limit.");

  ALOGI("Current nofile limit is %llu/%llu.", rlim.rlim_cur, rlim.rlim_max);
  rlim.rlim_cur = rlim.rlim_max;
  ret = setrlimit64(RLIMIT_NOFILE, &rlim);
  ALOGE_IF(ret < 0, "Failed to set nofile limit, error=%s", strerror(errno));

  rlim.rlim_cur = -1;
  rlim.rlim_max = -1;
  if (getrlimit64(RLIMIT_NOFILE, &rlim) < 0)
    ALOGE("Failed to get nofile limit.");
  else
    ALOGI("New nofile limit is %llu/%llu.", rlim.rlim_cur, rlim.rlim_max);

  dispatcher = android::pdx::ServiceDispatcher::Create();
  CHECK_ERROR(!dispatcher, error, "Failed to create service dispatcher\n");

  service = android::dvr::BufferHubService::Create();
  CHECK_ERROR(!service, error, "Failed to create buffer hub service\n");
  dispatcher->AddService(service);

  // Set the main bufferhubd thread to use SCHED_FIFO.
  // TODO(b/70536062): fifo_medium is likely to be 79 on most systems and this
  // choice was made by VR team when bufferhub is only used by VR. We need to
  // find a more sensible priority level before making bufferhub used by the
  // entire Android stack.
  param.sched_priority = fifo_medium;
  ret = sched_setscheduler(0, SCHED_FIFO, &param);
  if (ret < 0) {
    ALOGE("Failed to set SCHED_FIFO priority, errno=%d.", errno);
  } else {
    ALOGE("Set SCHED_FIFO priority to %d", fifo_medium);
  }

  ALOGI("Entering message loop.");

  ret = dispatcher->EnterDispatchLoop();
  CHECK_ERROR(ret < 0, error, "Dispatch loop exited because: %s\n",
              strerror(-ret));

error:
  return -ret;
}
