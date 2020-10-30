/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */

#include <binder/Parcel.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <vibrator/ExternalVibration.h>

using namespace android;

constexpr size_t kMaxStringLength = 100;
constexpr audio_content_type_t kAudioContentType[] = {
    AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_CONTENT_TYPE_SPEECH, AUDIO_CONTENT_TYPE_MUSIC,
    AUDIO_CONTENT_TYPE_MOVIE, AUDIO_CONTENT_TYPE_SONIFICATION};
constexpr audio_usage_t kAudioUsage[] = {
    AUDIO_USAGE_UNKNOWN,
    AUDIO_USAGE_MEDIA,
    AUDIO_USAGE_VOICE_COMMUNICATION,
    AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
    AUDIO_USAGE_ALARM,
    AUDIO_USAGE_NOTIFICATION,
    AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
    AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST,
    AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT,
    AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED,
    AUDIO_USAGE_NOTIFICATION_EVENT,
    AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
    AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
    AUDIO_USAGE_ASSISTANCE_SONIFICATION,
    AUDIO_USAGE_GAME,
    AUDIO_USAGE_VIRTUAL_SOURCE,
    AUDIO_USAGE_ASSISTANT,
    AUDIO_USAGE_CALL_ASSISTANT,
    AUDIO_USAGE_EMERGENCY,
    AUDIO_USAGE_SAFETY,
    AUDIO_USAGE_VEHICLE_STATUS,
    AUDIO_USAGE_ANNOUNCEMENT,
};
constexpr audio_source_t kAudioSource[] = {
    AUDIO_SOURCE_DEFAULT,           AUDIO_SOURCE_MIC,
    AUDIO_SOURCE_VOICE_UPLINK,      AUDIO_SOURCE_VOICE_DOWNLINK,
    AUDIO_SOURCE_VOICE_CALL,        AUDIO_SOURCE_CAMCORDER,
    AUDIO_SOURCE_VOICE_RECOGNITION, AUDIO_SOURCE_VOICE_COMMUNICATION,
    AUDIO_SOURCE_REMOTE_SUBMIX,     AUDIO_SOURCE_UNPROCESSED,
    AUDIO_SOURCE_VOICE_PERFORMANCE, AUDIO_SOURCE_ECHO_REFERENCE,
    AUDIO_SOURCE_FM_TUNER,
};
constexpr size_t kAudioContentTypeNum = std::size(kAudioContentType);
constexpr size_t kAudioUsageNum = std::size(kAudioUsage);
constexpr size_t kAudioSourceNum = std::size(kAudioSource);

class TestVibrationController : public os::IExternalVibrationController {
   public:
    explicit TestVibrationController() {}
    IBinder *onAsBinder() override { return nullptr; }
    binder::Status mute(/*out*/ bool *ret) override {
        *ret = false;
        return binder::Status::ok();
    };
    binder::Status unmute(/*out*/ bool *ret) override {
        *ret = false;
        return binder::Status::ok();
    };
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    std::string pkg = fdp.ConsumeRandomLengthString(kMaxStringLength);
    audio_attributes_t attributes;
    attributes.content_type =
        kAudioContentType[fdp.ConsumeIntegralInRange<uint32_t>(0, kAudioContentTypeNum - 1)];
    attributes.usage = kAudioUsage[fdp.ConsumeIntegralInRange<uint32_t>(0, kAudioUsageNum - 1)];
    attributes.source = kAudioSource[fdp.ConsumeIntegralInRange<uint32_t>(0, kAudioSourceNum - 1)];
    attributes.flags = fdp.ConsumeIntegral<uint32_t>();
    sp<TestVibrationController> vibrationController = new TestVibrationController();
    if (!vibrationController) {
        return 0;
    }
    sp<os::ExternalVibration> extVibration =
        new os::ExternalVibration(uid, pkg, attributes, vibrationController);
    if (!extVibration) {
        return 0;
    }
    extVibration->getUid();
    extVibration->getPackage();
    extVibration->getAudioAttributes();
    extVibration->getController();

    Parcel parcel;
    parcel.writeInt32(uid);
    parcel.writeString16(String16(pkg.c_str()));
    parcel.writeStrongBinder(IInterface::asBinder(vibrationController));
    extVibration->readFromParcel(&parcel);
    extVibration->writeToParcel(&parcel);
    return 0;
}
