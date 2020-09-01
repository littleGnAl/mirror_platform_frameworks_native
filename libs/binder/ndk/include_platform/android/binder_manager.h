/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <android/binder_ibinder.h>
#include <android/binder_status.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * This registers the service with the default service manager under this instance name. This does
 * not take ownership of binder.
 *
 * \param binder object to register globally with the service manager.
 * \param instance identifier of the service. This will be used to lookup the service.
 *
 * \return EX_NONE on success.
 */
binder_exception_t AServiceManager_addService(AIBinder* binder, const char* instance);

/**
 * Gets a binder object with this specific instance name. Will return nullptr immediately if the
 * service is not available This also implicitly calls AIBinder_incStrong (so the caller of this
 * function is responsible for calling AIBinder_decStrong).
 *
 * \param instance identifier of the service used to lookup the service.
 */
__attribute__((warn_unused_result)) AIBinder* AServiceManager_checkService(const char* instance);

/**
 * Gets a binder object with this specific instance name. Blocks for a couple of seconds waiting on
 * it. This also implicitly calls AIBinder_incStrong (so the caller of this function is responsible
 * for calling AIBinder_decStrong).
 *
 * \param instance identifier of the service used to lookup the service.
 */
__attribute__((warn_unused_result)) AIBinder* AServiceManager_getService(const char* instance);

/**
 * Registers a lazy service with the default service manager under the 'instance' name.
 * Does not take ownership of binder.
 * The service must be configured statically with init so it can be restarted with
 * ctl.interface.* messages from servicemanager.
 * AServiceManager_registerLazyService cannot safely be used with AServiceManager_addService
 * in the same process. If one service is registered with AServiceManager_registerLazyService,
 * the entire process will have its lifetime controlled by servicemanager.
 * Instead, all services in the process should be registered using
 * AServiceManager_registerLazyService.
 *
 * \param binder object to register globally with the service manager.
 * \param instance identifier of the service. This will be used to lookup the service.
 *
 * \return STATUS_OK on success.
 */
binder_status_t AServiceManager_registerLazyService(AIBinder* binder, const char* instance)
        __INTRODUCED_IN(31);

/**
 * Gets a binder object with this specific instance name. Efficiently waits for the service.
 * If the service is not declared, it will wait indefinitely. Requires the threadpool
 * to be started in the service.
 * This also implicitly calls AIBinder_incStrong (so the caller of this function is responsible
 * for calling AIBinder_decStrong).
 *
 * \param instance identifier of the service used to lookup the service.
 *
 * \return service if registered, null if not.
 */
__attribute__((warn_unused_result)) AIBinder* AServiceManager_waitForService(const char* instance)
        __INTRODUCED_IN(31);

/**
 * Check if a service is declared (e.g. VINTF manifest).
 *
 * \param instance identifier of the service.
 *
 * \return true on success, meaning AServiceManager_waitForService should always
 *    be able to return the service.
 */
bool AServiceManager_isDeclared(const char* instance) __INTRODUCED_IN(31);

/**
 * Prevent lazy services without client from shutting down their process
 *
 * \param persist 'true' if the process should not exit.
 */
void AServiceManager_forceLazyServicesPersist(bool persist) __INTRODUCED_IN(31);

/**
 * Set a callback which is called when the number of lazy services with clients
 * changes.
 *
 * \param callback function to call when the number of services
 *    with clients changes.
 * \param context opaque pointer passed back as second parameter to the
 * callback.
 *
 * The callback takes two arguments. The first is the number of registered
 * lazy services for this process which have clients.
 * The second is the 'context' pointer passed during the registration.
 *
 * Callback return value:
 * - false: Default behavior for lazy services (shut down the process if there
 *          are no clients).
 * - true:  Don't shut down the process even if there are no clients.
 *
 * This callback gives a chance to:
 * 1 - Perform some additional operations before exiting;
 * 2 - Prevent the process from exiting by returning "true" from the callback.
 */
void AServiceManager_setActiveServicesCountCallback(bool (*callback)(int, void*), void* context)
        __INTRODUCED_IN(31);

/**
 * Try to unregister all services previously registered with 'registerService'.
 *
 * \return true on success.
 */
bool AServiceManager_tryUnregister() __INTRODUCED_IN(31);

/**
 * Re-register services that were unregistered by 'tryUnregister'.
 * This method should be called in the case 'tryUnregister' fails
 * (and should be called on the same thread).
 */
void AServiceManager_reRegister() __INTRODUCED_IN(31);

__END_DECLS
