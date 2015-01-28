/**
 * @file sensor.h
 */
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


#ifndef ANDROID_SENSOR_H
#define ANDROID_SENSOR_H

/******************************************************************
 *
 * IMPORTANT NOTICE:
 *
 *   This file is part of Android's set of stable system headers
 *   exposed by the Android NDK (Native Development Kit).
 *
 *   Third-party source AND binary code relies on the definitions
 *   here to be FROZEN ON ALL UPCOMING PLATFORM RELEASES.
 *
 *   - DO NOT MODIFY ENUMS (EXCEPT IF YOU ADD NEW 32-BIT VALUES)
 *   - DO NOT MODIFY CONSTANTS OR FUNCTIONAL MACROS
 *   - DO NOT CHANGE THE SIGNATURE OF FUNCTIONS IN ANY WAY
 *   - DO NOT CHANGE THE LAYOUT OR SIZE OF STRUCTURES
 */

/*
 * Structures and functions to receive and process sensor events in
 * native code.
 *
 */

#include <sys/types.h>

#include <android/looper.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Sensor types
 * (keep in sync with hardware/sensor.h)
 */
enum {
/// TODO: DOCUMENT
    ASENSOR_TYPE_ACCELEROMETER      = 1,
/// TODO: DOCUMENT
    ASENSOR_TYPE_MAGNETIC_FIELD     = 2,
/// TODO: DOCUMENT
    ASENSOR_TYPE_GYROSCOPE          = 4,
/// TODO: DOCUMENT
    ASENSOR_TYPE_LIGHT              = 5,
/// TODO: DOCUMENT
    ASENSOR_TYPE_PROXIMITY          = 8
};

/// Sensor accuracy measure

enum {
/// TODO: DOCUMENT
    ASENSOR_STATUS_NO_CONTACT       = -1,
/// TODO: DOCUMENT
    ASENSOR_STATUS_UNRELIABLE       = 0,
/// TODO: DOCUMENT
    ASENSOR_STATUS_ACCURACY_LOW     = 1,
/// TODO: DOCUMENT
    ASENSOR_STATUS_ACCURACY_MEDIUM  = 2,
/// TODO: DOCUMENT
    ASENSOR_STATUS_ACCURACY_HIGH    = 3
};

/// Sensor Reporting Modes.
enum {
/// TODO: DOCUMENT
    AREPORTING_MODE_CONTINUOUS = 0,
/// TODO: DOCUMENT
    AREPORTING_MODE_ON_CHANGE = 1,
/// TODO: DOCUMENT
    AREPORTING_MODE_ONE_SHOT = 2,
/// TODO: DOCUMENT
    AREPORTING_MODE_SPECIAL_TRIGGER = 3
};

/*
 * A few useful constants
 */

/// Earth's gravity in m/s^2
#define ASENSOR_STANDARD_GRAVITY            (9.80665f)
/// Maximum magnetic field on Earth's surface in uT
#define ASENSOR_MAGNETIC_FIELD_EARTH_MAX    (60.0f)
/// Minimum magnetic field on Earth's surface in uT
#define ASENSOR_MAGNETIC_FIELD_EARTH_MIN    (30.0f)

/*
 * A sensor event.
 */

/// NOTE: Must match hardware/sensors.h
typedef struct ASensorVector {
/// TODO: DOCUMENT
    union {
/// TODO: DOCUMENT
        float v[3];
/// TODO: DOCUMENT
        struct {
/// TODO: DOCUMENT
            float x;
/// TODO: DOCUMENT
            float y;
/// TODO: DOCUMENT
            float z;
        };
/// TODO: DOCUMENT
        struct {
/// TODO: DOCUMENT
            float azimuth;
/// TODO: DOCUMENT
            float pitch;
/// TODO: DOCUMENT
            float roll;
        };
    };
/// TODO: DOCUMENT
    int8_t status;
/// TODO: DOCUMENT
    uint8_t reserved[3];
} ASensorVector;

/// TODO: DOCUMENT
typedef struct AMetaDataEvent {
/// TODO: DOCUMENT
    int32_t what;
/// TODO: DOCUMENT
    int32_t sensor;
} AMetaDataEvent;

/// TODO: DOCUMENT
typedef struct AUncalibratedEvent {
/// TODO: DOCUMENT
  union {
/// TODO: DOCUMENT
    float uncalib[3];
/// TODO: DOCUMENT
    struct {
/// TODO: DOCUMENT
      float x_uncalib;
/// TODO: DOCUMENT
      float y_uncalib;
/// TODO: DOCUMENT
      float z_uncalib;
    };
  };
/// TODO: DOCUMENT
  union {
/// TODO: DOCUMENT
    float bias[3];
/// TODO: DOCUMENT
    struct {
/// TODO: DOCUMENT
      float x_bias;
/// TODO: DOCUMENT
      float y_bias;
/// TODO: DOCUMENT
      float z_bias;
    };
  };
} AUncalibratedEvent;

/// TODO: DOCUMENT
typedef struct AHeartRateEvent {
/// TODO: DOCUMENT
  float bpm;
/// TODO: DOCUMENT
  int8_t status;
} AHeartRateEvent;

/// Must match hardware/sensors.h
typedef struct ASensorEvent {
/// TODO: DOCUMENT
    int32_t version; /* sizeof(struct ASensorEvent) */
/// TODO: DOCUMENT
    int32_t sensor;
/// TODO: DOCUMENT
    int32_t type;
/// TODO: DOCUMENT
    int32_t reserved0;
/// TODO: DOCUMENT
    int64_t timestamp;
/// TODO: DOCUMENT
    union {
/// TODO: DOCUMENT
        union {
/// TODO: DOCUMENT
            float           data[16];
/// TODO: DOCUMENT
            ASensorVector   vector;
/// TODO: DOCUMENT
            ASensorVector   acceleration;
/// TODO: DOCUMENT
            ASensorVector   magnetic;
/// TODO: DOCUMENT
            float           temperature;
/// TODO: DOCUMENT
            float           distance;
/// TODO: DOCUMENT
            float           light;
/// TODO: DOCUMENT
            float           pressure;
/// TODO: DOCUMENT
            float           relative_humidity;
/// TODO: DOCUMENT
            AUncalibratedEvent uncalibrated_gyro;
/// TODO: DOCUMENT
            AUncalibratedEvent uncalibrated_magnetic;
/// TODO: DOCUMENT
            AMetaDataEvent meta_data;
/// TODO: DOCUMENT
            AHeartRateEvent heart_rate;
        };
/// TODO: DOCUMENT
        union {
/// TODO: DOCUMENT
            uint64_t        data[8];
/// TODO: DOCUMENT
            uint64_t        step_counter;
        } u64;
    };

/// TODO: DOCUMENT
    uint32_t flags;
/// TODO: DOCUMENT
    int32_t reserved1[3];
} ASensorEvent;

/// TODO: DOCUMENT
struct ASensorManager;
/// TODO: DOCUMENT
typedef struct ASensorManager ASensorManager;

/// TODO: DOCUMENT
struct ASensorEventQueue;
/// TODO: DOCUMENT
typedef struct ASensorEventQueue ASensorEventQueue;

/// TODO: DOCUMENT
struct ASensor;
/// TODO: DOCUMENT
typedef struct ASensor ASensor;
/// TODO: DOCUMENT
typedef ASensor const* ASensorRef;
/// TODO: DOCUMENT
typedef ASensorRef const* ASensorList;

/*****************************************************************************/

/**
 * Get a reference to the sensor manager. ASensorManager is a singleton.
 *
 * Example:
 *
 *     ASensorManager* sensorManager = ASensorManager_getInstance();
 *
 */
ASensorManager* ASensorManager_getInstance();


/// Returns the list of available sensors.
int ASensorManager_getSensorList(ASensorManager* manager, ASensorList* list);

/**
 * Returns the default sensor for the given type, or NULL if no sensor
 * of that type exists.
 */
ASensor const* ASensorManager_getDefaultSensor(ASensorManager* manager, int type);

/**
 * Returns the default sensor with the given type and wakeUp properties or NULL if no sensor
 * of this type and wakeUp properties exists.
 */
ASensor const* ASensorManager_getDefaultSensorEx(ASensorManager* manager, int type,
        bool wakeUp);

/// Creates a new sensor event queue and associate it with a looper.
ASensorEventQueue* ASensorManager_createEventQueue(ASensorManager* manager,
        ALooper* looper, int ident, ALooper_callbackFunc callback, void* data);

/// Destroys the event queue and frees all resources associated to it.
int ASensorManager_destroyEventQueue(ASensorManager* manager, ASensorEventQueue* queue);


/*****************************************************************************/

/// Enable the selected sensor. Returns a negative error code on failure.
int ASensorEventQueue_enableSensor(ASensorEventQueue* queue, ASensor const* sensor);

/// Disable the selected sensor. Returns a negative error code on failure.
int ASensorEventQueue_disableSensor(ASensorEventQueue* queue, ASensor const* sensor);

/**
 * Sets the delivery rate of events in microseconds for the given sensor.
 * Note that this is a hint only, generally event will arrive at a higher
 * rate. It is an error to set a rate inferior to the value returned by
 * ASensor_getMinDelay().
 * Returns a negative error code on failure.
 */
int ASensorEventQueue_setEventRate(ASensorEventQueue* queue, ASensor const* sensor, int32_t usec);

/**
 * Returns true if there are one or more events available in the
 * sensor queue.  Returns 1 if the queue has events; 0 if
 * it does not have events; and a negative value if there is an error.
 */
int ASensorEventQueue_hasEvents(ASensorEventQueue* queue);

/**
 * Returns the next available events from the queue.  Returns a negative
 * value if no events are available or an error has occurred, otherwise
 * the number of events returned.
 *
 * Examples:
 *   ASensorEvent event;
 *   ssize_t numEvent = ASensorEventQueue_getEvents(queue, &event, 1);
 *
 *   ASensorEvent eventBuffer[8];
 *   ssize_t numEvent = ASensorEventQueue_getEvents(queue, eventBuffer, 8);
 *
 */
ssize_t ASensorEventQueue_getEvents(ASensorEventQueue* queue,
                ASensorEvent* events, size_t count);


/*****************************************************************************/

/// Returns this sensor's name (non localized)
const char* ASensor_getName(ASensor const* sensor);

/// eturns this sensor's vendor's name (non localized)
const char* ASensor_getVendor(ASensor const* sensor);

/// Return this sensor's type
int ASensor_getType(ASensor const* sensor);

/// Returns this sensors's resolution
float ASensor_getResolution(ASensor const* sensor);

/**
 * Returns the minimum delay allowed between events in microseconds.
 * A value of zero means that this sensor doesn't report events at a
 * constant rate, but rather only when a new data is available.
 */
int ASensor_getMinDelay(ASensor const* sensor);

/**
 * Returns the maximum size of batches for this sensor. Batches will often be
 * smaller, as the hardware fifo might be used for other sensors.
 */
int ASensor_getFifoMaxEventCount(ASensor const* sensor);

/// Returns the hardware batch fifo size reserved to this sensor.
int ASensor_getFifoReservedEventCount(ASensor const* sensor);

/// Returns this sensor's string type.
const char* ASensor_getStringType(ASensor const* sensor);

/// Returns the reporting mode for this sensor. One of AREPORTING_MODE_* constants.
int ASensor_getReportingMode(ASensor const* sensor);

/// Returns true if this is a wake up sensor, false otherwise.
bool ASensor_isWakeUpSensor(ASensor const* sensor);

#ifdef __cplusplus
};
#endif

#endif // ANDROID_SENSOR_H
