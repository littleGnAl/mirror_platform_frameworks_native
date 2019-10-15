#pragma once

/*
 * Copyright (C) 2019 The Android Open Source Project
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

#if defined(__linux__)


#include <sys/epoll.h>

#include <deque>
#include <list>
#include <mutex>
#include <unordered_map>

#include <adbwifi/sysdeps/sysdeps.h>
#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>

#include "adbwifi/fdevent/fdevent.h"

namespace adbwifi {
namespace fdevent {

struct fdevent_context_epoll final : public fdevent_context {
    fdevent_context_epoll();
    virtual ~fdevent_context_epoll();

    virtual void Register(fdevent* fde) final;
    virtual void Unregister(fdevent* fde) final;

    virtual void Set(fdevent* fde, unsigned events) final;

    virtual void Loop() final;
    size_t InstalledCount() final;

  protected:
    virtual void Interrupt() final;

  public:
    // All operations to fdevent should happen only in the main thread.
    // That's why we don't need a lock for fdevent.
    std::unordered_map<int, fdevent*> epoll_node_map_;
    std::list<fdevent*> pending_list_;

    android::base::unique_fd epoll_fd_;
    android::base::unique_fd interrupt_fd_;
    fdevent* interrupt_fde_ = nullptr;
};

#endif  // defined(__linux__)

}  // namespace fdevent
}  // namespace adbwifi
