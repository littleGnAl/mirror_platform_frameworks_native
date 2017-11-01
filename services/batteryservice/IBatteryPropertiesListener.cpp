/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <stdint.h>
#include <sys/types.h>
#include <batteryservice/IBatteryPropertiesListener.h>
#include <binder/Parcel.h>

namespace android {

class BpBatteryPropertiesListener : public BpInterface<IBatteryPropertiesListener>
{
public:
    explicit BpBatteryPropertiesListener(const sp<IBinder>& impl)
        : BpInterface<IBatteryPropertiesListener>(impl)
    {
    }

    void batteryPropertiesChanged(struct BatteryProperties props)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IBatteryPropertiesListener::getInterfaceDescriptor());
        data.writeInt32(1);
        props.writeToParcel(&data);
        remote()->transact(TRANSACT_BATTERYPROPERTIESCHANGED, data, &reply, IBinder::FLAG_ONEWAY);
    }
};

IMPLEMENT_META_INTERFACE(BatteryPropertiesListener, "android.os.IBatteryPropertiesListener");

// ----------------------------------------------------------------------------

status_t BnBatteryPropertiesListener::onTransact(uint32_t code, const Parcel& data,
                                                 Parcel* reply, uint32_t flags)
{
    switch(code) {
        case TRANSACT_BATTERYPROPERTIESCHANGED: {
            CHECK_INTERFACE(IBatteryPropertiesListener, data, reply);
            struct BatteryProperties props = {};
            if (data.readInt32() != 0) {
                props.readFromParcel((Parcel*)&data);
            }
            batteryPropertiesChanged(props);
            return NO_ERROR;
        }
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
};

}; // namespace android
