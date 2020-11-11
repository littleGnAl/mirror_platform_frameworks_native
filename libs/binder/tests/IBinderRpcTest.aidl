/*
 * Copyright (C) 2020 The Android Open Source Project
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

interface IBinderRpcTest {
    oneway void sendString(@utf8InCpp String str);
    @utf8InCpp String doubleString(@utf8InCpp String str);


    // Caller sends server, callee pings caller's server and returns error code.
    int pingMe(IBinder binder);
    IBinder repeatBinder(IBinder binder);

    // Idea is client creates its own instance of IBinderRpcTest and calls this,
    // and the server calls 'binder' with (calls - 1) passing itself as 'binder',
    // going back and forth until calls = 0
    void nestMe(IBinderRpcTest binder, int calls);
}
