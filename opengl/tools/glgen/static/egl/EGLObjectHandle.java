/*
**
** Copyright 2012, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

package android.opengl;

/**
 * Base class for wrapped EGL objects.
 *
 */
public abstract class EGLObjectHandle {
    private final long mHandle;

    // TODO Deprecate EGLObjectHandle(int) method
    protected EGLObjectHandle(int handle) {
        mHandle = handle;
    }
    // TODO Unhide the EGLObjectHandle(long) method
    /**
     * {@hide}
     */
    protected EGLObjectHandle(long handle) {
        mHandle = handle;
    }
    // TODO Deprecate getHandle() method in favor of getNativeHandle()
    /**
     * Returns the native handle of the wrapped EGL object. This handle can be
     * cast to the corresponding native type on the native side.
     *
     * For example, EGLDisplay dpy = (EGLDisplay)handle;
     *
     * @return the native handle of the wrapped EGL object.
     */
    public int getHandle() {
        return (int)mHandle;
    }

    // TODO Unhide getNativeHandle() method
    /**
     * {@hide}
     */
    public long getNativeHandle() {
        return mHandle;
    }
    @Override
    public int hashCode() {
        /*
         * Based on the algorithm suggested in
         * http://developer.android.com/reference/java/lang/Object.html
         */
        int result = 17;
        result = 31 * result + (int) (mHandle ^ (mHandle >>> 32));
        return result;
    }
}
