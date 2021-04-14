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
package com.android.tests.binder;

import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;
import com.android.tradefed.util.RunUtil;
import com.android.tradefed.util.TargetFileUtils;
import java.io.File;
import java.util.ArrayList;
import java.util.NoSuchElementException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

// TODO: Set up adb forwarding and actually run the tests.

@RunWith(DeviceJUnit4ClassRunner.class)
public class BinderRpcHostTest extends BaseHostJUnit4Test {
    // Temporary dir in device.
    private static final String DEVICE_TEMP_DIR = "/data/local/tmp/";
    // binderRpcTest test binary name
    private static final String BINDER_RPC_TEST_BINARY = "binderRpcTest";
    private RunUtil runUtil = new RunUtil();
    private ITestDevice mDevice;

    @Before
    public void setUp() throws Exception {
        mDevice = getDevice();
    }

    @Test
    public void testHostNothing() throws Exception {
        File testBin = getHostTestBinary();
        String[] cmds = {testBin.getAbsolutePath()};
        long timeoutMs = 5 * 60 * 1000;
        CommandResult result = runUtil.runTimedCmd(timeoutMs, cmds);
        Assert.assertEquals(
                "Test failed: " + result.getStderr(), CommandStatus.SUCCESS, result.getStatus());
    }

    @Test
    public void testDeviceNothing() throws Exception {
        String testBinPath = getDeviceTestBinary();

        String chmodCommand = String.format("chmod 755 %s", testBinPath);
        CLog.d(chmodCommand);
        CommandResult cmdResult = mDevice.executeShellV2Command(chmodCommand);
        Assert.assertEquals("Unable to chmod:" + cmdResult.getStderr(), cmdResult.getStatus(),
                CommandStatus.SUCCESS);

        String testCommand = String.format("%s", testBinPath);
        CLog.d(testCommand);
        cmdResult = mDevice.executeShellV2Command(testCommand);
        Assert.assertEquals("Unable to run test:" + cmdResult.getStderr(), cmdResult.getStatus(),
                CommandStatus.SUCCESS);
    }

    private String getDeviceTestBinary() throws Exception {
        String testBinPath = null;
        ArrayList<String> matchedResults =
                TargetFileUtils.findFile(DEVICE_TEMP_DIR, BINDER_RPC_TEST_BINARY, null, mDevice);
        for (String matchedResult : matchedResults) {
            if (!mDevice.isDirectory(matchedResult)) {
                testBinPath = matchedResult;
                break;
            }
        }
        if (testBinPath == null) {
            throw new NoSuchElementException(
                    String.format("Cannot find %s on device", BINDER_RPC_TEST_BINARY));
        }
        return testBinPath;
    }

    private File getHostTestBinary() throws Exception {
        return getTestInformation().getDependencyFile(BINDER_RPC_TEST_BINARY, false);
    }
}
