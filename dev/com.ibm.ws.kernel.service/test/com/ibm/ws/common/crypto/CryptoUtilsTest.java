/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.common.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 *
 */
public class CryptoUtilsTest {

    @Test
    public void testFipsEnabled_fipsLevel_140_3_ibmJcePlusFipsAvailable() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-3");
            mock.when(CryptoUtils::isIBMJCEPlusFIPSAvailable).thenReturn(true);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertTrue("Expected FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_140_3_openJcePlusFipsAvailable() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-3");
            mock.when(CryptoUtils::isIBMJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSAvailable).thenReturn(true);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertTrue("Expected FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_140_3_ibmJcePlusFipsProviderAvailable() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-3");
            mock.when(CryptoUtils::isIBMJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isIBMJCEPlusFIPSProviderAvailable).thenReturn(true);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertTrue("Expected FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_140_3_openJcePlusFipsProviderAvailable() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-3");
            mock.when(CryptoUtils::isIBMJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isIBMJCEPlusFIPSProviderAvailable).thenReturn(false);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSProviderAvailable).thenReturn(true);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertTrue("Expected FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_140_3_noProvidersAvailable() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-3");
            mock.when(CryptoUtils::isIBMJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isIBMJCEPlusFIPSProviderAvailable).thenReturn(false);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSProviderAvailable).thenReturn(false);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_140_2_useFipsProvider_true_fipsProviderName_ibmJcePlusFips() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-2");
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("true");
            mock.when(CryptoUtils::getFipsProviderName).thenReturn("IBMJCEPlusFIPS");
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());
            assertTrue("Expected FIPS 140-2 to be enabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_140_2_useFipsProvider_true_fipsProviderName_openJcePlusFips() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-2");
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("true");
            mock.when(CryptoUtils::getFipsProviderName).thenReturn("OpenJCEPlusFIPS");
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_140_2_useFipsProvider_true_fipsProviderName_noProviderName() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-2");
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("true");
            mock.when(CryptoUtils::getFipsProviderName).thenReturn("NO_PROVIDER_NAME");
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_140_2_useFipsProvider_false() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-2");
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("false");
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_140_2_useFipsProvider_invalid() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-2");
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("abc");
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_disabled() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("disabled");
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

    @Test
    public void testFipsEnabled_fipsLevel_invalid() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("abc");
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            CryptoUtils.fips140_3Checked = false;
            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());
            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());
        }
    }

}
