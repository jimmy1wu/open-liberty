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

import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 *
 */
public class CryptoUtilsTest {

    @Before
    public void setUp() {
        // Reset the cached values to ensure test isolation.
        CryptoUtils.isEnhancedSecurityChecked = false;
        CryptoUtils.fips140_3Checked = false;
        CryptoUtils.semeruFips140_3Checked = false;
    }

    // ==========================================================================================================
    //
    // isFips140_3Enabled Tests
    //
    // ==========================================================================================================

    @Test
    public void testIsFips140_3Enabled_fipsLevel_140_3_isIbmJava8Fips140_3SetAndFipsProviderAvailable_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-3");
            mock.when(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable).thenReturn(true);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();

            assertTrue("Expected FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isFips140_3Enabled());

            mock.verify(CryptoUtils::getFipsLevel, Mockito.times(1));
            mock.verify(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_3Enabled_fipsLevel_140_3_isIbmJava8Fips140_3SetAndFipsProviderAvailable_false_openJcePlusFipsAvailable_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-3");
            mock.when(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable).thenReturn(false);
            mock.when(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable).thenReturn(true);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();

            assertTrue("Expected FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isFips140_3Enabled());

            mock.verify(CryptoUtils::getFipsLevel, Mockito.times(1));
            mock.verify(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_3Enabled_fipsLevel_140_3_isIbmJava8Fips140_3SetAndFipsProviderAvailable_false_openJcePlusFipsAvailable_false() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-3");
            mock.when(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable).thenReturn(false);
            mock.when(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable).thenReturn(false);
            mock.when(CryptoUtils::useEnhancedSecurityAlgorithms).thenReturn(false);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());

            mock.verify(CryptoUtils::getFipsLevel, Mockito.times(1));
            mock.verify(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::useEnhancedSecurityAlgorithms, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_3Enabled_fipsLevel_140_2() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("140-2");
            mock.when(CryptoUtils::useEnhancedSecurityAlgorithms).thenReturn(false);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());

            mock.verify(CryptoUtils::getFipsLevel, Mockito.times(1));
            mock.verify(CryptoUtils::useEnhancedSecurityAlgorithms, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_3Enabled_fipsLevel_disabled() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("disabled");
            mock.when(CryptoUtils::useEnhancedSecurityAlgorithms).thenReturn(false);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());

            mock.verify(CryptoUtils::getFipsLevel, Mockito.times(1));
            mock.verify(CryptoUtils::useEnhancedSecurityAlgorithms, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_3Enabled_fipsLevel_invalid() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("abc");
            mock.when(CryptoUtils::useEnhancedSecurityAlgorithms).thenReturn(false);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isFips140_3Enabled());

            mock.verify(CryptoUtils::getFipsLevel, Mockito.times(1));
            mock.verify(CryptoUtils::useEnhancedSecurityAlgorithms, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_3Enabled_fipsLevel_disabled_useEnhancedSecurityAlgorithms_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::getFipsLevel).thenReturn("disabled");
            mock.when(CryptoUtils::useEnhancedSecurityAlgorithms).thenReturn(true);
            mock.when(CryptoUtils::isFips140_3Enabled).thenCallRealMethod();

            assertTrue("Expected FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isFips140_3Enabled());

            mock.verify(CryptoUtils::getFipsLevel, Mockito.times(1));
            mock.verify(CryptoUtils::useEnhancedSecurityAlgorithms, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    // ==========================================================================================================
    //
    // isFips140_2Enabled Tests
    //
    // ==========================================================================================================

    @Test
    public void testIsFips140_2Enabled_isFips140_3Enabled_false_getUseFipsProvider_true_getFipsProviderName_IBMJCEPlusFIPS() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(false);
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("true");
            mock.when(CryptoUtils::getFipsProviderName).thenReturn("IBMJCEPlusFIPS");
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            assertTrue("Expected FIPS 140-2 to be enabled, but was disabled.", CryptoUtils.isFips140_2Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::getUseFipsProvider, Mockito.times(1));
            mock.verify(CryptoUtils::getFipsProviderName, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_2Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_2Enabled_isFips140_3Enabled_false_getUseFipsProvider_true_getFipsProviderName_IBMJCEPlus() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(false);
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("true");
            mock.when(CryptoUtils::getFipsProviderName).thenReturn("IBMJCEPlus");
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::getUseFipsProvider, Mockito.times(1));
            mock.verify(CryptoUtils::getFipsProviderName, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_2Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_2Enabled_isFips140_3Enabled_false_getUseFipsProvider_true_getFipsProviderName_OpenJCEPlusFIPS() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(false);
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("true");
            mock.when(CryptoUtils::getFipsProviderName).thenReturn("OpenJCEPlusFIPS");
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::getUseFipsProvider, Mockito.times(1));
            mock.verify(CryptoUtils::getFipsProviderName, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_2Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_2Enabled_isFips140_3Enabled_false_getUseFipsProvider_true_getFipsProviderName_OpenJCEPlus() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(false);
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("true");
            mock.when(CryptoUtils::getFipsProviderName).thenReturn("OpenJCEPlus");
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::getUseFipsProvider, Mockito.times(1));
            mock.verify(CryptoUtils::getFipsProviderName, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_2Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_2Enabled_isFips140_3Enabled_false_getUseFipsProvider_true_getFipsProviderName_invalid() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(false);
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("true");
            mock.when(CryptoUtils::getFipsProviderName).thenReturn("abc");
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::getUseFipsProvider, Mockito.times(1));
            mock.verify(CryptoUtils::getFipsProviderName, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_2Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_2Enabled_isFips140_3Enabled_false_getUseFipsProvider_false() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(false);
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("false");
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::getUseFipsProvider, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_2Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_2Enabled_isFips140_3Enabled_false_getUseFipsProvider_invalid() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(false);
            mock.when(CryptoUtils::getUseFipsProvider).thenReturn("abc");
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::getUseFipsProvider, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_2Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsFips140_2Enabled_isFips140_3Enabled_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(true);
            mock.when(CryptoUtils::isFips140_2Enabled).thenCallRealMethod();

            assertFalse("Expected FIPS 140-2 to be disabled, but was enabled.", CryptoUtils.isFips140_2Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::isFips140_2Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    // ==========================================================================================================
    //
    // isSemeruFips140_3Enabled Tests
    //
    // ==========================================================================================================

    @Test
    public void testIsSemeruFips140_3Enabled_isFips140_3Enabled_true_isSemeruFipsTrueAndFips140_3ProviderAvailable_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(true);
            mock.when(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable).thenReturn(true);
            mock.when(CryptoUtils::isSemeruFips140_3Enabled).thenCallRealMethod();

            assertTrue("Expected Semeru FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isSemeruFips140_3Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsSemeruFips140_3Enabled_isFips140_3Enabled_true_isSemeruFipsTrueAndFips140_3ProviderAvailable_false() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(true);
            mock.when(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable).thenReturn(false);
            mock.when(CryptoUtils::useEnhancedSecurityAlgorithms).thenReturn(false);
            mock.when(CryptoUtils::isSemeruFips140_3Enabled).thenCallRealMethod();

            assertFalse("Expected Semeru FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isSemeruFips140_3Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::useEnhancedSecurityAlgorithms, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsSemeruFips140_3Enabled_isFips140_3Enabled_false() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(false);
            mock.when(CryptoUtils::useEnhancedSecurityAlgorithms).thenReturn(false);
            mock.when(CryptoUtils::isSemeruFips140_3Enabled).thenCallRealMethod();

            assertFalse("Expected Semeru FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isSemeruFips140_3Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::useEnhancedSecurityAlgorithms, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsSemeruFips140_3Enabled_isFips140_3Enabled_false_useEnhancedSecurityAlgorithms_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isFips140_3Enabled).thenReturn(false);
            mock.when(CryptoUtils::useEnhancedSecurityAlgorithms).thenReturn(true);
            mock.when(CryptoUtils::isSemeruFips140_3Enabled).thenCallRealMethod();

            assertTrue("Expected Semeru FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isSemeruFips140_3Enabled());

            mock.verify(CryptoUtils::isFips140_3Enabled, Mockito.times(1));
            mock.verify(CryptoUtils::useEnhancedSecurityAlgorithms, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFips140_3Enabled, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    // ==========================================================================================================
    //
    // isIbmJava8Fips140_3SetAndFipsProviderAvailable Tests
    //
    // ==========================================================================================================

    @Test
    public void testIsIbmJava8Fips140_3SetAndFipsProviderAvailable_isIbmJava8Fips140_3_true_isIBMJCEPlusFIPSAvailable_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isIbmJava8Fips140_3).thenReturn(true);
            mock.when(CryptoUtils::isIBMJCEPlusFIPSAvailable).thenReturn(true);
            mock.when(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable).thenCallRealMethod();

            assertTrue("Expected IBM Java 8 FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isIbmJava8Fips140_3SetAndFipsProviderAvailable());

            mock.verify(CryptoUtils::isIbmJava8Fips140_3, Mockito.times(1));
            mock.verify(CryptoUtils::isIBMJCEPlusFIPSAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsIbmJava8Fips140_3SetAndFipsProviderAvailable_isIbmJava8Fips140_3_true_isIBMJCEPlusFIPSAvailable_false_isIBMJCEPlusFIPSProviderAvailable_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isIbmJava8Fips140_3).thenReturn(true);
            mock.when(CryptoUtils::isIBMJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isIBMJCEPlusFIPSProviderAvailable).thenReturn(true);
            mock.when(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable).thenCallRealMethod();

            assertTrue("Expected IBM Java 8 FIPS 140-3 to be enabled, but was disabled.", CryptoUtils.isIbmJava8Fips140_3SetAndFipsProviderAvailable());

            mock.verify(CryptoUtils::isIbmJava8Fips140_3, Mockito.times(1));
            mock.verify(CryptoUtils::isIBMJCEPlusFIPSAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isIBMJCEPlusFIPSProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsIbmJava8Fips140_3SetAndFipsProviderAvailable_isIbmJava8Fips140_3_true_isIBMJCEPlusFIPSAvailable_false_isIBMJCEPlusFIPSProviderAvailable_false() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isIbmJava8Fips140_3).thenReturn(true);
            mock.when(CryptoUtils::isIBMJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isIBMJCEPlusFIPSProviderAvailable).thenReturn(false);
            mock.when(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable).thenCallRealMethod();

            assertFalse("Expected IBM Java 8 FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isIbmJava8Fips140_3SetAndFipsProviderAvailable());

            mock.verify(CryptoUtils::isIbmJava8Fips140_3, Mockito.times(1));
            mock.verify(CryptoUtils::isIBMJCEPlusFIPSAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isIBMJCEPlusFIPSProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsIbmJava8Fips140_3SetAndFipsProviderAvailable_isIbmJava8Fips140_3_false() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isIbmJava8Fips140_3).thenReturn(false);
            mock.when(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable).thenCallRealMethod();

            assertFalse("Expected IBM Java 8 FIPS 140-3 to be disabled, but was enabled.", CryptoUtils.isIbmJava8Fips140_3SetAndFipsProviderAvailable());

            mock.verify(CryptoUtils::isIbmJava8Fips140_3, Mockito.times(1));
            mock.verify(CryptoUtils::isIbmJava8Fips140_3SetAndFipsProviderAvailable, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    // ==========================================================================================================
    //
    // isSemeruFipsTrueAndFips140_3ProviderAvailable Tests
    //
    // ==========================================================================================================

    @Test
    public void testIsSemeruFipsTrueAndFips140_3ProviderAvailable_isSemeruFips_true_isOpenJCEPlusFIPSAvailable_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isSemeruFips).thenReturn(true);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSAvailable).thenReturn(true);
            mock.when(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable).thenCallRealMethod();

            assertTrue("Expected Semeru FIPS to be enabled, but was disabled.", CryptoUtils.isSemeruFipsTrueAndFips140_3ProviderAvailable());

            mock.verify(CryptoUtils::isSemeruFips, Mockito.times(1));
            mock.verify(CryptoUtils::isOpenJCEPlusFIPSAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsSemeruFipsTrueAndFips140_3ProviderAvailable_isSemeruFips_true_isOpenJCEPlusFIPSAvailable_false_isOpenJCEPlusFIPSProviderAvailable_true() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isSemeruFips).thenReturn(true);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSProviderAvailable).thenReturn(true);
            mock.when(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable).thenCallRealMethod();

            assertTrue("Expected Semeru FIPS to be enabled, but was disabled.", CryptoUtils.isSemeruFipsTrueAndFips140_3ProviderAvailable());

            mock.verify(CryptoUtils::isSemeruFips, Mockito.times(1));
            mock.verify(CryptoUtils::isOpenJCEPlusFIPSAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isOpenJCEPlusFIPSProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsSemeruFipsTrueAndFips140_3ProviderAvailable_isSemeruFips_true_isOpenJCEPlusFIPSAvailable_false_isOpenJCEPlusFIPSProviderAvailable_false() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isSemeruFips).thenReturn(true);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSAvailable).thenReturn(false);
            mock.when(CryptoUtils::isOpenJCEPlusFIPSProviderAvailable).thenReturn(false);
            mock.when(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable).thenCallRealMethod();

            assertFalse("Expected Semeru FIPS to be disabled, but was enabled.", CryptoUtils.isSemeruFipsTrueAndFips140_3ProviderAvailable());

            mock.verify(CryptoUtils::isSemeruFips, Mockito.times(1));
            mock.verify(CryptoUtils::isOpenJCEPlusFIPSAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isOpenJCEPlusFIPSProviderAvailable, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

    @Test
    public void testIsSemeruFipsTrueAndFips140_3ProviderAvailable_isSemeruFips_false() {
        try (MockedStatic<CryptoUtils> mock = Mockito.mockStatic(CryptoUtils.class)) {
            mock.when(CryptoUtils::isSemeruFips).thenReturn(false);
            mock.when(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable).thenCallRealMethod();

            assertFalse("Expected Semeru FIPS to be disabled, but was enabled.", CryptoUtils.isSemeruFipsTrueAndFips140_3ProviderAvailable());

            mock.verify(CryptoUtils::isSemeruFips, Mockito.times(1));
            mock.verify(CryptoUtils::isSemeruFipsTrueAndFips140_3ProviderAvailable, Mockito.times(1));
            mock.verifyNoMoreInteractions();
        }
    }

}
