/*
 * Copyright (C) 2009 The Android Open Source Project
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

#include <algorithm>
#include <chrono>
#include <thread>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <binder/TextOutput.h>
#include <utils/Vector.h>

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "dumpsys.h"

using namespace android;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteFully;

static int sort_func(const String16* lhs, const String16* rhs)
{
    return lhs->compare(*rhs);
}

static void usage() {
    fprintf(
        stderr,
        "usage: dumpsys\n"
        "         To dump all services to stdout.\n"
        "or:\n"
        "       dumpsys [-t TIMEOUT] [-d DIR] [--help | -l | --skip SERVICES | [-o FILE ] SERVICE "
        "[ARGS]]\n"
        "         --help: shows this help\n"
        "         -d DIR: dumps services in the given directory, using a service.txt file for each "
        "service\n"
        "         -l: only list services, do not dump them\n"
        "         -t TIMEOUT: TIMEOUT to use in seconds instead of default 10 seconds\n"
        "         --skip SERVICES: dumps all services but SERVICES (comma-separated list)\n"
        "         -o FILE: dumps the specific service in the given file (or stdout if not set)\n"
        "         SERVICE [ARGS]: dumps only service SERVICE, optionally passing ARGS to it\n");
}

static bool IsSkipped(const Vector<String16>& skipped, const String16& service) {
    for (const auto& candidate : skipped) {
        if (candidate == service) {
            return true;
        }
    }
    return false;
}

static int OpenFile(const std::string& path) {
    int fd =
        TEMP_FAILURE_RETRY(open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
    if (fd < 0) {
        fprintf(stderr, "Failed to open file %s: %s\n", path.c_str(), strerror(errno));
        exit(1);
    }
    return fd;
}

int Dumpsys::main(int argc, char* const argv[]) {
    Vector<String16> services;
    Vector<String16> args;
    Vector<String16> skipped_services;
    bool show_list_only = false;
    bool skip_services = false;
    int timeout_arg = 10;
    std::string dump_dir = "";
    std::string dump_file = "";

    static struct option long_options[] = {
        {"skip", no_argument, 0, 0},
        {"help", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    // Must reset optind, otherwise subsequent calls will fail (wouldn't happen on main.cpp, but
    // happens on test cases).
    optind = 1;
    while (1) {
        int c;
        int option_index = 0;

        c = getopt_long(argc, argv, "+t:ld:o:", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            if (!strcmp(long_options[option_index].name, "skip")) {
                skip_services = true;
            } else if (!strcmp(long_options[option_index].name, "help")) {
                usage();
                return 0;
            }
            break;

        case 't':
            {
                char *endptr;
                timeout_arg = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || timeout_arg <= 0) {
                    fprintf(stderr, "Error: invalid timeout number: '%s'\n", optarg);
                    return -1;
                }
            }
            break;

        case 'l':
            show_list_only = true;
            break;

        case 'd':
            dump_dir = optarg;
            break;

        case 'o':
            dump_file = optarg;
            break;

        default:
            fprintf(stderr, "\n");
            usage();
            return -1;
        }
    }

    for (int i = optind; i < argc; i++) {
        if (skip_services) {
            skipped_services.add(String16(argv[i]));
        } else {
            if (i == optind) {
                services.add(String16(argv[i]));
            } else {
                args.add(String16(argv[i]));
            }
        }
    }

    if (!dump_dir.empty() && !services.empty()) {
        fprintf(stderr, "Cannot use -d on a single service; use -o instead\n");
        return 1;
    }

    if (!dump_file.empty() && services.empty()) {
        fprintf(stderr, "Cannot use -o on multiples services; use -d instead\n");
        return 1;
    }

    if ((skip_services && skipped_services.empty()) ||
        (show_list_only && (!services.empty() || !skipped_services.empty()))) {
        usage();
        return -1;
    }

    if (services.empty() || show_list_only) {
        // gets all services
        services = sm_->listServices();
        services.sort(sort_func);
        args.add(String16("-a"));
    }

    const size_t N = services.size();
    bool dump_on_dir = !dump_dir.empty();
    bool dump_on_file = !dump_file.empty();

    if (N > 1) {
        // first print a list of the current services
        aout << "Currently running services:" << endl;

        for (size_t i=0; i<N; i++) {
            sp<IBinder> service = sm_->checkService(services[i]);

            if (service != nullptr) {
                bool skipped = IsSkipped(skipped_services, services[i]);
                aout << "  " << services[i] << (skipped ? " (skipped)" : "") << endl;
            }
        }
    }

    if (show_list_only) {
        return 0;
    }

    int fd = STDOUT_FILENO;

    for (size_t i = 0; i < N; i++) {
        String16 service_name = std::move(services[i]);
        if (IsSkipped(skipped_services, service_name)) continue;

        sp<IBinder> service = sm_->checkService(service_name);
        if (service != nullptr) {
            int sfd[2];

            if (pipe(sfd) != 0) {
                aerr << "Failed to create pipe to dump service info for " << service_name
                     << ": " << strerror(errno) << endl;
                continue;
            }

            if (N > 1) {
                if (dump_on_dir) {
                    std::string path = dump_dir + "/" + String16::std_string(service_name) + ".txt";
                    fd = OpenFile(path);
                    aout << "DUMP OF SERVICE " << service_name << " ON " << path << endl;
                } else {
                    aout << "------------------------------------------------------------"
                            "-------------------"
                         << endl;
                    aout << "DUMP OF SERVICE " << service_name << ":" << endl;
                }
            } else {
                if (dump_on_file) {
                    fd = OpenFile(dump_file);
                }
            }

            unique_fd local_end(sfd[0]);
            unique_fd remote_end(sfd[1]);
            sfd[0] = sfd[1] = -1;

            // dump blocks until completion, so spawn a thread..
            std::thread dump_thread([=, remote_end { std::move(remote_end) }]() mutable {
                int err = service->dump(remote_end.get(), args);

                // It'd be nice to be able to close the remote end of the socketpair before the dump
                // call returns, to terminate our reads if the other end closes their copy of the
                // file descriptor, but then hangs for some reason. There doesn't seem to be a good
                // way to do this, though.
                remote_end.reset();

                if (err != 0) {
                    aerr << "Error dumping service info: (" << strerror(err) << ") " << service_name
                         << endl;
                }
            });

            auto timeout = std::chrono::seconds(timeout_arg);
            auto start = std::chrono::steady_clock::now();
            auto end = start + timeout;

            struct pollfd pfd = {
                .fd = local_end.get(),
                .events = POLLIN
            };

            bool timed_out = false;
            bool error = false;
            while (true) {
                // Wrap this in a lambda so that TEMP_FAILURE_RETRY recalculates the timeout.
                auto time_left_ms = [end]() {
                    auto now = std::chrono::steady_clock::now();
                    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - now);
                    return std::max(diff.count(), 0ll);
                };

                int rc = TEMP_FAILURE_RETRY(poll(&pfd, 1, time_left_ms()));
                if (rc < 0) {
                    aerr << "Error in poll while dumping service " << service_name << " : "
                         << strerror(errno) << endl;
                    error = true;
                    break;
                } else if (rc == 0) {
                    timed_out = true;
                    break;
                }

                char buf[4096];
                rc = TEMP_FAILURE_RETRY(read(local_end.get(), buf, sizeof(buf)));
                if (rc < 0) {
                    aerr << "Failed to read while dumping service " << service_name << ": "
                         << strerror(errno) << endl;
                    error = true;
                    break;
                } else if (rc == 0) {
                    // EOF.
                    break;
                }

                if (!WriteFully(fd, buf, rc)) {
                    aerr << "Failed to write while dumping service " << service_name << ": "
                         << strerror(errno) << endl;
                    error = true;
                    break;
                }
            }

            if (timed_out) {
                aout << endl
                     << "*** SERVICE '" << service_name << "' DUMP TIMEOUT (" << timeout_arg
                     << "s) EXPIRED ***" << endl
                     << endl;
            }

            if (timed_out || error) {
                dump_thread.detach();
            } else {
                dump_thread.join();
            }

            if (N > 1) {
              std::chrono::duration<double> elapsed_seconds =
                  std::chrono::steady_clock::now() - start;
              if (dump_on_dir) {
                  dprintf(fd, "--------- %.3fs was the duration\n", elapsed_seconds.count());
              } else {
                  aout << StringPrintf("--------- %.3fs ", elapsed_seconds.count()).c_str()
                       << "was the duration of dumpsys " << service_name << endl;
              }
            }
        } else {
            aerr << "Can't find service: " << service_name << endl;
        }
    }

    return 0;
}
