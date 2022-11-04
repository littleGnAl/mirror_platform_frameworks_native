#pragma once

#include <aidl/android/frameworks/sensorservice/BnSensorManager.h>
#include <jni.h>


namespace android {
namespace frameworks {
namespace sensorservice {
namespace implementation {

class SensorManagerAidl : public ::aidl::android::frameworks::sensorservice::BnSensorManager {
    public:
     explicit SensorManagerAidl(JavaVM* vm);
    ~SensorManagerAidl();

  ::ndk::ScopedAStatus createAshmemDirectChannel(const ::aidl::android::hardware::common::Ashmem& in_mem, int64_t in_size, std::shared_ptr<::aidl::android::frameworks::sensorservice::IDirectReportChannel>* _aidl_return) override;
  ::ndk::ScopedAStatus createEventQueue(const std::shared_ptr<::aidl::android::frameworks::sensorservice::IEventQueueCallback>& in_callback, std::shared_ptr<::aidl::android::frameworks::sensorservice::IEventQueue>* _aidl_return) override;
  ::ndk::ScopedAStatus createGrallocDirectChannel(const ::ndk::ScopedFileDescriptor& in_buffer, int64_t in_size, std::shared_ptr<::aidl::android::frameworks::sensorservice::IDirectReportChannel>* _aidl_return) override;
  ::ndk::ScopedAStatus getDefaultSensor(::aidl::android::hardware::sensors::SensorType in_type, ::aidl::android::hardware::sensors::SensorInfo* _aidl_return) override;
  ::ndk::ScopedAStatus getSensorList(std::vector<::aidl::android::hardware::sensors::SensorInfo>* _aidl_return) override;
};

}  // namespace implementation
}  // namespace sensorservice
}  // namespace frameworks
}  // namespace android
