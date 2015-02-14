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

enum {
    // Default dimensions before setDefaultBufferSize is called
    DEFAULT_WIDTH = 1,
    DEFAULT_HEIGHT = 1,

    // Default format before setDefaultBufferFormat is called
    DEFAULT_FORMAT = HAL_PIXEL_FORMAT_RGBA_8888,

    // Default transform hint before setTransformHint is called
    DEFAULT_TRANSFORM_HINT = 0,
};

const int DEFAULT_CONSUMER_USAGE_BITS = 0;
// One past the end of the last 'query' enum value. Update this if we add more enums.
const int NATIVE_WINDOW_QUERY_LAST_OFF_BY_ONE = NATIVE_WINDOW_CONSUMER_USAGE_BITS + 1;
