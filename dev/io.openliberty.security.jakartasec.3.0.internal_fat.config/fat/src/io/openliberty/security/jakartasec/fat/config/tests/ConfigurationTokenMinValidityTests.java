/*******************************************************************************
 * Copyright (c) 2023 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.security.jakartasec.fat.config.tests;

import java.util.List;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.ibm.ws.security.fat.common.utils.SecurityFatHttpUtils;

import componenttest.annotation.Server;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.rules.repeater.RepeatTests;
import componenttest.topology.impl.LibertyServer;
import io.openliberty.security.jakartasec.fat.commonTests.CommonAnnotatedSecurityTests;
import io.openliberty.security.jakartasec.fat.configs.TestConfigMaps;
import io.openliberty.security.jakartasec.fat.utils.CommonExpectations;
import io.openliberty.security.jakartasec.fat.utils.Constants;
import io.openliberty.security.jakartasec.fat.utils.ShrinkWrapHelpers;

/**
 * Tests @OpenIdAuthenticationMechanismDefinition useNonce and useNonceExpression
 */
/**
 * Tests appSecurity-5.0
 */
@SuppressWarnings("restriction")
@RunWith(FATRunner.class)
public class ConfigurationTokenMinValidityTests extends CommonAnnotatedSecurityTests {

    protected static Class<?> thisClass = ConfigurationTokenMinValidityTests.class;

    @Server("jakartasec-3.0_fat.config.op")
    public static LibertyServer opServer;
    @Server("jakartasec-3.0_fat.config.rp.tokenMinValidity")
    public static LibertyServer rpServer;

    protected static ShrinkWrapHelpers swh = null;

    @ClassRule
    public static RepeatTests repeat = createRandomTokenTypeRepeats();

    private static int TOKEN_LIFETIME_SECONDS = 20;
    private static int BUFFER_SECONDS = 2;

    @BeforeClass
    public static void setUp() throws Exception {

        // write property that is used to configure the OP to generate JWT or Opaque tokens
        setTokenTypeInBootstrap(opServer);

        // Add servers to server trackers that will be used to clean servers up and prevent servers
        // from being restored at the end of each test (so far, the tests are not reconfiguring the servers)
        updateTrackers(opServer, rpServer, false);

        List<String> waitForMsgs = null;
        opServer.startServerUsingExpandedConfiguration("server_tokenMinValidity.xml", waitForMsgs);
        SecurityFatHttpUtils.saveServerPorts(opServer, Constants.BVT_SERVER_1_PORT_NAME_ROOT);
        opHttpBase = "http://localhost:" + opServer.getBvtPort();
        opHttpsBase = "https://localhost:" + opServer.getBvtSecurePort();

        rpServer.startServerUsingExpandedConfiguration("server_orig.xml", waitForMsgs);
        SecurityFatHttpUtils.saveServerPorts(rpServer, Constants.BVT_SERVER_2_PORT_NAME_ROOT);

        rpHttpBase = "http://localhost:" + rpServer.getBvtPort();
        rpHttpsBase = "https://localhost:" + rpServer.getBvtSecurePort();

        deployMyApps(); // run this after starting the RP so we have the rp port to update the openIdConfig.properties file within the apps

    }

    /**
     * Deploy the apps that this test class uses
     *
     * @throws Exception
     */
    public static void deployMyApps() throws Exception {

        swh = new ShrinkWrapHelpers(opHttpBase, opHttpsBase, rpHttpBase, rpHttpsBase);

        swh.defaultDropinApp(rpServer, "TokenMinValidity5s.war", "oidc.client.tokenMinValidity5s.servlets", "oidc.client.base.*");
        swh.defaultDropinApp(rpServer, "TokenMinValidity20s.war", "oidc.client.tokenMinValidity20s.servlets", "oidc.client.base.*");
        swh.defaultDropinApp(rpServer, "TokenMinValidity0s.war", "oidc.client.tokenMinValidity0s.servlets", "oidc.client.base.*");
        swh.defaultDropinApp(rpServer, "TokenMinValidityMinus5s.war", "oidc.client.tokenMinValidityMinus5s.servlets", "oidc.client.base.*");
        swh.defaultDropinApp(rpServer, "TokenMinValidityDefault.war", "oidc.client.tokenMinValidityDefault.servlets", "oidc.client.base.*");

        swh.deployConfigurableTestApps(rpServer, "TokenMinValidityEL5s.war", "TokenMinValidityEL.war",
                                       buildUpdatedConfigMap(opServer, rpServer, "TokenMinValidityEL5s", "allValues.openIdConfig.properties",
                                                             TestConfigMaps.getTokenMinValidity5s()),
                                       "oidc.client.tokenMinValidityEL.servlets", "oidc.client.base.*");
        swh.deployConfigurableTestApps(rpServer, "TokenMinValidityEL20s.war", "TokenMinValidityEL.war",
                                       buildUpdatedConfigMap(opServer, rpServer, "TokenMinValidityEL20s", "allValues.openIdConfig.properties",
                                                             TestConfigMaps.getTokenMinValidity20s()),
                                       "oidc.client.tokenMinValidityEL.servlets", "oidc.client.base.*");
        swh.deployConfigurableTestApps(rpServer, "TokenMinValidityEL0s.war", "TokenMinValidityEL.war",
                                       buildUpdatedConfigMap(opServer, rpServer, "TokenMinValidityEL0s", "allValues.openIdConfig.properties",
                                                             TestConfigMaps.getTokenMinValidity0s()),
                                       "oidc.client.tokenMinValidityEL.servlets", "oidc.client.base.*");
        swh.deployConfigurableTestApps(rpServer, "TokenMinValidityELMinus5s.war", "TokenMinValidityEL.war",
                                       buildUpdatedConfigMap(opServer, rpServer, "TokenMinValidityELMinus5s", "allValues.openIdConfig.properties",
                                                             TestConfigMaps.getTokenMinValidityMinus5s()),
                                       "oidc.client.tokenMinValidityEL.servlets", "oidc.client.base.*");
        swh.deployConfigurableTestApps(rpServer, "TokenMinValidity5sEL15s.war", "TokenMinValidity5sWithEL.war",
                                       buildUpdatedConfigMap(opServer, rpServer, "TokenMinValidity5sEL15s", "allValues.openIdConfig.properties",
                                                             TestConfigMaps.getTokenMinValidity15s()),
                                       "oidc.client.tokenMinValidity5sWithEL.servlets", "oidc.client.base.*");

    }

    private void runGoodEndToEnd(String appRoot, String app, int tokenMinValiditySeconds) throws Exception {

        String url = rpHttpsBase + "/" + appRoot + "/" + app;

        WebClient webClient = getAndSaveWebClient();
        runGoodEndToEndTest(webClient, appRoot, app);

        actions.testLogAndSleep(TOKEN_LIFETIME_SECONDS - tokenMinValiditySeconds - BUFFER_SECONDS);
        invokeAppGetToApp(webClient, url);

        actions.testLogAndSleep(2 * BUFFER_SECONDS);
        invokeAppReturnLoginPage(webClient, url);

    }

    private void runBadEndToEnd(String appRoot, String app) throws Exception {

        String url = rpHttpsBase + "/" + appRoot + "/" + app;

        WebClient webClient = getAndSaveWebClient();
        Page response = invokeAppReturnLoginPage(webClient, url);

        response = actions.doFormLogin(response, Constants.TESTUSER, Constants.TESTUSERPWD);
        validationUtils.validateResult(response, CommonExpectations.successfullyReachedOidcLoginPage());

    }

    @Test
    public void ConfigurationTokenMinValidityTests_tokenMinValidity_5s() throws Exception {

        runGoodEndToEnd("TokenMinValidity5s", "TokenMinValidity5sServlet", 5);

    }

    @Test
    public void ConfigurationTokenMinValidityTests_tokenMinValidity_20s() throws Exception {

        runBadEndToEnd("TokenMinValidity20s", "TokenMinValidity20sServlet");

    }

    @Test
    public void ConfigurationTokenMinValidityTests_tokenMinValidity_0s() throws Exception {

        runGoodEndToEnd("TokenMinValidity0s", "TokenMinValidity0sServlet", 0);

    }

    @Test
    public void ConfigurationTokenMinValidityTests_tokenMinValidity_minus5s() throws Exception {

        runBadEndToEnd("TokenMinValidityMinus5s", "TokenMinValidityMinus5sServlet");

    }

    @Test
    public void ConfigurationTokenMinValidityTests_EL_5s() throws Exception {

        runGoodEndToEnd("TokenMinValidityEL5s", "TokenMinValidityELServlet", 5);

    }

    @Test
    public void ConfigurationTokenMinValidityTests_EL_20s() throws Exception {

        runBadEndToEnd("TokenMinValidityEL20s", "TokenMinValidityELServlet");

    }

    @Test
    public void ConfigurationTokenMinValidityTests_EL_0s() throws Exception {

        runGoodEndToEnd("TokenMinValidityEL0s", "TokenMinValidityELServlet", 0);

    }

    @Test
    public void ConfigurationTokenMinValidityTests_EL_minus5s() throws Exception {

        runBadEndToEnd("TokenMinValidityELMinus5s", "TokenMinValidityELServlet");

    }

    @Test
    public void ConfigurationTokenMinValidityTests_tokenMinValidity_5s_EL_15s() throws Exception {

        runGoodEndToEnd("TokenMinValidity5sEL15s", "TokenMinValidity5sWithELServlet", 15);

    }

    @Test
    public void ConfigurationTokenMinValidityTests_tokenMinValidity_default() throws Exception {

        runGoodEndToEnd("TokenMinValidityDefault", "TokenMinValidityDefaultServlet", 10);

    }

}
