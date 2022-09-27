/*
 * Copyright (C) 2022 Google LLC
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

package android.test.stats;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.frameworks.stats.IStats;
import android.frameworks.stats.VendorAtom;
import android.frameworks.stats.VendorAtomValue;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Log;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class VtsVendorAtomJavaTest {
    private static final String TAG = "VtsTest";
    Optional<IStats> statsService;

    @Before
    public void setUp() {
        try {
            final String[] instances = ServiceManager.getDeclaredInstances(IStats.DESCRIPTOR);
            assertEquals(1, instances.length);
            assertEquals(instances[0], "default");

            final String instanceName = IStats.DESCRIPTOR + "/default";
            if (!ServiceManager.isDeclared(instanceName)) {
                Log.e(TAG, "IStats is not registered");
                statsService = Optional.empty();
            } else {
                statsService = Optional.ofNullable(
                    IStats.Stub.asInterface(ServiceManager.waitForDeclaredService(instanceName)));
            }
            assertTrue(statsService.isPresent());
        } catch (SecurityException e) {
            Log.e(TAG, "Failed to connect to IStats service", e);
        } catch (NullPointerException e) {
            Log.e(TAG, "Failed to connect to IStats service", e);
        }
    }

    /*
     * Test IStats::reportVendorAtom with all VendorAtomValue types, including empty string in
     * repeated string array and empty int array.
     */
    @Test
    public void testReportVendorAtom() {
        VendorAtom atom = new VendorAtom();
        atom.reverseDomainName = "";
        atom.atomId = 104999;
        atom.values = new VendorAtomValue[12];

        atom.values[0] = VendorAtomValue.intValue(7);
        atom.values[1] = VendorAtomValue.longValue(70000);
        atom.values[2] = VendorAtomValue.floatValue((float) 8.5);
        atom.values[3] = VendorAtomValue.stringValue("test");
        atom.values[4] = VendorAtomValue.boolValue(true);
        atom.values[5] = VendorAtomValue.repeatedIntValue(new int[] {1, 2});
        atom.values[6] = VendorAtomValue.repeatedLongValue(new long[] {430000, 500000, 1000001});
        atom.values[7] =
            VendorAtomValue.repeatedFloatValue(new float[] {(float) 7.9, (float) 1.2, (float) 5.4});
        atom.values[8] =
            VendorAtomValue.repeatedStringValue(new java.lang.String[] {"test1", "", "test2"});
        atom.values[9] = VendorAtomValue.repeatedIntValue(new int[] {});
        atom.values[10] = VendorAtomValue.repeatedBoolValue(new boolean[] {false, true});
        atom.values[11] = VendorAtomValue.byteArrayValue(new byte[] {5, 10, 21});

        try {
            statsService.get().reportVendorAtom(atom);
        } catch (NoSuchElementException e) {
            Log.e(TAG, "Failed to get IStats service", e);
            fail();
        } catch (RemoteException e) {
            Log.e(TAG, "Failed to log atom to IStats service", e);
            fail();
        }
    }

    /*
     * Test IStats::reportVendorAtom with null fields.
     */
    @Test
    public void testReportVendorAtomNull() {
        VendorAtom atom = new VendorAtom();
        atom.reverseDomainName = "";
        atom.atomId = 104999;
        atom.values = new VendorAtomValue[9];

        atom.values[0] = VendorAtomValue.intValue(8);
        atom.values[1] = VendorAtomValue.repeatedIntValue(null);
        atom.values[2] = VendorAtomValue.repeatedLongValue(null);
        atom.values[3] = VendorAtomValue.repeatedFloatValue(null);
        atom.values[4] = VendorAtomValue.repeatedStringValue(null);
        atom.values[5] =
            VendorAtomValue.repeatedStringValue(new java.lang.String[] {null, "test2", null});
        atom.values[6] = VendorAtomValue.repeatedBoolValue(null);
        atom.values[7] = VendorAtomValue.byteArrayValue(null);
        atom.values[8] = VendorAtomValue.stringValue("test");

        try {
            statsService.get().reportVendorAtom(atom);
        } catch (NoSuchElementException e) {
            Log.e(TAG, "Failed to get IStats service", e);
            fail();
        } catch (RemoteException e) {
            Log.e(TAG, "Failed to log atom to IStats service", e);
            fail();
        }
    }
}
