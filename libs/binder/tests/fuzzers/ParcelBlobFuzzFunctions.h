/*
 * Copyright 2020 The Android Open Source Project
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

#ifndef PARCELBLOB_FUZZER_FUNCTIONS_H_
#define PARCELBLOB_FUZZER_FUNCTIONS_H_

#include <fuzzer/FuzzedDataProvider.h>
#include <commonFuzzHelpers.h>
#include <binder/Parcel.h>

namespace android {

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 *
 *  NOTE: While both readable/writable inherit from Blob, we can't actually use
 *        that to consolidate calls as Blob is private to the Parcel class.
 */
static const std::vector<
        std::function<void(FuzzedDataProvider*, std::vector<std::shared_ptr<Parcel::ReadableBlob>>*,
                           std::vector<std::shared_ptr<Parcel::WritableBlob>>*)>>
        parcelBlob_operations = {
                // create new readableBlob
                [](FuzzedDataProvider*,
                   std::vector<std::shared_ptr<Parcel::ReadableBlob>>* rBlobVector,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>*) -> void {
                    std::shared_ptr<Parcel::ReadableBlob> new_blob(new Parcel::ReadableBlob());
                    rBlobVector->push_back(new_blob);
                },

                // create new writableBlob
                [](FuzzedDataProvider*, std::vector<std::shared_ptr<Parcel::ReadableBlob>>*,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>* wBlobVector) -> void {
                    std::shared_ptr<Parcel::WritableBlob> new_blob(new Parcel::WritableBlob());
                    wBlobVector->push_back(new_blob);
                },

                // Delete a readable blob
                [](FuzzedDataProvider* fdp,
                   std::vector<std::shared_ptr<Parcel::ReadableBlob>>* rBlobVector,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>*) -> void {
                    // Delete the object & remove from vector
                    size_t to_delete_index =
                            fdp->ConsumeIntegralInRange<size_t>(0, rBlobVector->size() - 1);
                    rBlobVector->erase(rBlobVector->begin() + to_delete_index);
                },

                // Delete a writable blob
                [](FuzzedDataProvider* fdp, std::vector<std::shared_ptr<Parcel::ReadableBlob>>*,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>* wBlobVector) -> void {
                    // Delete the object & remove from vector
                    size_t to_delete_index =
                            fdp->ConsumeIntegralInRange<size_t>(0, wBlobVector->size() - 1);
                    wBlobVector->erase(wBlobVector->begin() + to_delete_index);
                },

                // readable clear
                [](FuzzedDataProvider* fdp,
                   std::vector<std::shared_ptr<Parcel::ReadableBlob>>* rBlobVector,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>*) -> void {
                    std::shared_ptr<Parcel::ReadableBlob> blob =
                            getArbitraryVectorElement(fdp, *rBlobVector, false);
                    blob->clear();
                },

                // writable clear
                [](FuzzedDataProvider* fdp, std::vector<std::shared_ptr<Parcel::ReadableBlob>>*,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>* wBlobVector) -> void {
                    std::shared_ptr<Parcel::WritableBlob> blob =
                            getArbitraryVectorElement(fdp, *wBlobVector, false);
                    blob->clear();
                },

                // readable release
                [](FuzzedDataProvider* fdp,
                   std::vector<std::shared_ptr<Parcel::ReadableBlob>>* rBlobVector,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>*) -> void {
                    std::shared_ptr<Parcel::ReadableBlob> blob =
                            getArbitraryVectorElement(fdp, *rBlobVector, false);
                    blob->release();
                },

                // writable release
                [](FuzzedDataProvider* fdp, std::vector<std::shared_ptr<Parcel::ReadableBlob>>*,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>* wBlobVector) -> void {
                    std::shared_ptr<Parcel::WritableBlob> blob =
                            getArbitraryVectorElement(fdp, *wBlobVector, false);
                    blob->release();
                },

                // readable size
                [](FuzzedDataProvider* fdp,
                   std::vector<std::shared_ptr<Parcel::ReadableBlob>>* rBlobVector,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>*) -> void {
                    std::shared_ptr<Parcel::ReadableBlob> blob =
                            getArbitraryVectorElement(fdp, *rBlobVector, false);
                    blob->size();
                },

                // writable size
                [](FuzzedDataProvider* fdp, std::vector<std::shared_ptr<Parcel::ReadableBlob>>*,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>* wBlobVector) -> void {
                    std::shared_ptr<Parcel::WritableBlob> blob =
                            getArbitraryVectorElement(fdp, *wBlobVector, false);
                    blob->size();
                },

                // readable fd
                [](FuzzedDataProvider* fdp,
                   std::vector<std::shared_ptr<Parcel::ReadableBlob>>* rBlobVector,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>*) -> void {
                    std::shared_ptr<Parcel::ReadableBlob> blob =
                            getArbitraryVectorElement(fdp, *rBlobVector, false);
                    blob->fd();
                },

                // writable fd
                [](FuzzedDataProvider* fdp, std::vector<std::shared_ptr<Parcel::ReadableBlob>>*,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>* wBlobVector) -> void {
                    std::shared_ptr<Parcel::WritableBlob> blob =
                            getArbitraryVectorElement(fdp, *wBlobVector, false);
                    blob->fd();
                },

                // readable isMutable
                [](FuzzedDataProvider* fdp,
                   std::vector<std::shared_ptr<Parcel::ReadableBlob>>* rBlobVector,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>*) -> void {
                    std::shared_ptr<Parcel::ReadableBlob> blob =
                            getArbitraryVectorElement(fdp, *rBlobVector, false);
                    blob->isMutable();
                },

                // writable isMutable
                [](FuzzedDataProvider* fdp, std::vector<std::shared_ptr<Parcel::ReadableBlob>>*,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>* wBlobVector) -> void {
                    std::shared_ptr<Parcel::WritableBlob> blob =
                            getArbitraryVectorElement(fdp, *wBlobVector, false);
                    blob->isMutable();
                },

                // readable data
                [](FuzzedDataProvider* fdp,
                   std::vector<std::shared_ptr<Parcel::ReadableBlob>>* rBlobVector,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>*) -> void {
                    std::shared_ptr<Parcel::ReadableBlob> blob =
                            getArbitraryVectorElement(fdp, *rBlobVector, false);
                    blob->data();
                },

                // writable data
                [](FuzzedDataProvider* fdp, std::vector<std::shared_ptr<Parcel::ReadableBlob>>*,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>* wBlobVector) -> void {
                    std::shared_ptr<Parcel::WritableBlob> blob =
                            getArbitraryVectorElement(fdp, *wBlobVector, false);
                    blob->data();
                },

                // readable mutableData
                [](FuzzedDataProvider* fdp,
                   std::vector<std::shared_ptr<Parcel::ReadableBlob>>* rBlobVector,
                   std::vector<std::shared_ptr<Parcel::WritableBlob>>*) -> void {
                    std::shared_ptr<Parcel::ReadableBlob> blob =
                            getArbitraryVectorElement(fdp, *rBlobVector, false);
                    blob->mutableData();
                }};
} // namespace android
#endif // PARCELBLOB_FUZZER_FUNCTIONS_H_
